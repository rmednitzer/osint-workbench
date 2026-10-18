import json
import sys

from .errors import WorkbenchError
from .local_encoder import verified_file
from .local_reranker import RerankerManifest


def main():
    try:
        from .inference_state import bind_parent_lifetime

        bind_parent_lifetime()
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        packet = json.loads(sys.stdin.buffer.read(2 * 1024 * 1024))
        manifest = RerankerManifest.model_validate(packet["manifest"])
        model = verified_file(
            manifest.model_path, manifest.model_sha256, 512 * 1024**2, "MODEL_INTEGRITY_MISMATCH"
        )
        tokenizer = Tokenizer.from_str(
            verified_file(
                manifest.tokenizer_path,
                manifest.tokenizer_sha256,
                16 * 1024**2,
                "TOKENIZER_INTEGRITY_MISMATCH",
            ).decode()
        )
        tokenizer.no_truncation()
        tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = manifest.threads
        options.inter_op_num_threads = 1
        session = ort.InferenceSession(
            model, sess_options=options, providers=["CPUExecutionProvider"]
        )
        session.disable_fallback()
        inputs = session.get_inputs()
        if not inputs or any(
            v.name not in {"input_ids", "attention_mask", "token_type_ids"}
            or v.type != "tensor(int64)"
            for v in inputs
        ):
            raise WorkbenchError("RERANK_INCOMPATIBLE")
        scores = []
        for text in packet["texts"]:
            encoding = tokenizer.encode(packet["query"], text)
            if len(encoding.ids) > manifest.max_tokens:
                raise WorkbenchError("RERANK_INPUT_TOO_LONG")
            values = {
                "input_ids": encoding.ids,
                "attention_mask": encoding.attention_mask,
                "token_type_ids": encoding.type_ids,
            }
            output = session.run(
                [manifest.output_name],
                {item.name: np.asarray([values[item.name]], dtype=np.int64) for item in inputs},
            )[0]
            if output.ndim == 1 and output.shape == (1,) and manifest.positive_class == 0:
                value = output[0]
            elif (
                output.ndim == 2
                and output.shape[0] == 1
                and manifest.positive_class < output.shape[1]
            ):
                value = output[0, manifest.positive_class]
            else:
                raise WorkbenchError("RERANK_INCOMPATIBLE")
            if not np.isfinite(value):
                raise WorkbenchError("RERANK_INCOMPATIBLE")
            scores.append(float(value))
        sys.stdout.write(json.dumps({"scores": scores}, allow_nan=False))
    except WorkbenchError as exc:
        sys.stdout.write(json.dumps({"error": exc.code}))
        raise SystemExit(1) from None
    except Exception:
        sys.stdout.write(json.dumps({"error": "RERANK_UNAVAILABLE"}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
