"""Bounded CPU ONNX execution in a disposable process, not a model security sandbox."""

import json
import sys

from .errors import WorkbenchError
from .local_encoder import (
    MAX_PACKET_BYTES,
    MAX_RESULT,
    EncoderManifest,
    parse_packet,
    verified_file,
)
from .text import digest


class Runtime:
    def __init__(self, manifest: EncoderManifest):
        self.manifest = manifest
        model = verified_file(
            manifest.model_path,
            manifest.model_sha256,
            512 * 1024 * 1024,
            "MODEL_INTEGRITY_MISMATCH",
        )
        tokenizer = verified_file(
            manifest.tokenizer_path,
            manifest.tokenizer_sha256,
            16 * 1024 * 1024,
            "TOKENIZER_INTEGRITY_MISMATCH",
        )
        # Refuse unverified artifacts before native-library initialization,
        # which can discover devices and emit host-specific diagnostics.
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.tokenizer = Tokenizer.from_str(tokenizer.decode())
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = manifest.threads
        options.inter_op_num_threads = 1
        # Loading bytes cannot resolve external ONNX weight files relative to a model path.
        self.session = ort.InferenceSession(
            model, sess_options=options, providers=["CPUExecutionProvider"]
        )
        self.session.disable_fallback()
        inputs = self.session.get_inputs()
        self.inputs = {item.name for item in inputs}
        if (
            not self.inputs
            or not self.inputs <= {"input_ids", "attention_mask", "token_type_ids"}
            or any(item.type != "tensor(int64)" for item in inputs)
            or manifest.output_name not in {out.name for out in self.session.get_outputs()}
        ):
            raise WorkbenchError("ENCODER_INCOMPATIBLE")

    def vector(self, text, *, query=False):
        import numpy as np

        template = (
            self.manifest.space.query_template if query else self.manifest.space.document_template
        )
        encoding = self.tokenizer.encode(template.replace("{text}", text))
        if not encoding.ids or len(encoding.ids) > self.manifest.max_tokens:
            raise WorkbenchError("ENCODER_INPUT_TOO_LONG")
        values = {
            "input_ids": encoding.ids,
            "attention_mask": encoding.attention_mask,
            "token_type_ids": encoding.type_ids,
        }
        inputs = {name: np.asarray([values[name]], dtype=np.int64) for name in self.inputs}
        output = self.session.run([self.manifest.output_name], inputs)[0]
        pooling = self.manifest.space.pooling
        if pooling == "pooled" and output.ndim == 2 and output.shape[0] == 1:
            vector = output[0]
        elif output.ndim == 3 and output.shape[:2] == (1, len(encoding.ids)):
            if pooling == "cls":
                vector = output[0, 0]
            elif pooling == "mean":
                mask = np.asarray(encoding.attention_mask, dtype=np.float32)
                vector = (output[0] * mask[:, None]).sum(axis=0) / mask.sum()
            else:
                raise WorkbenchError("ENCODER_INCOMPATIBLE")
        else:
            raise WorkbenchError("ENCODER_INCOMPATIBLE")
        vector = np.asarray(vector, dtype=np.float32)
        norm = float(np.linalg.norm(vector))
        if not np.isfinite(norm) or norm == 0:
            raise WorkbenchError("INVALID_EMBEDDING_NORM")
        result = (vector / norm).tolist()
        self.manifest.space.validate_vector(result)
        return result

    def chunks(self, text):
        offsets = self.tokenizer.encode(text, add_special_tokens=False).offsets
        offsets = [(start, end) for start, end in offsets if end > start]
        if not offsets or any(not 0 <= a < b <= len(text) for a, b in offsets):
            raise WorkbenchError("TOKEN_OFFSETS_UNSUPPORTED")
        if any(offsets[i][0] > offsets[i + 1][0] for i in range(len(offsets) - 1)):
            raise WorkbenchError("TOKEN_OFFSETS_UNSUPPORTED")
        template = self.manifest.space.document_template
        overhead = len(self.tokenizer.encode(template.replace("{text}", "")).ids)
        budget = self.manifest.max_tokens - overhead - 4
        if budget <= self.manifest.overlap_tokens:
            raise WorkbenchError("ENCODER_INPUT_TOO_LONG")
        result, start_token = [], 0
        while start_token < len(offsets):
            end_token = min(len(offsets), start_token + budget)
            start = 0 if not result else offsets[start_token][0]
            while end_token > start_token:
                end = len(text) if end_token == len(offsets) else offsets[end_token][0]
                piece = text[start:end]
                if (
                    piece
                    and len(self.tokenizer.encode(template.replace("{text}", piece)).ids)
                    <= self.manifest.max_tokens
                ):
                    break
                end_token -= 1
            if end_token <= start_token or not piece:
                raise WorkbenchError("TOKEN_OFFSETS_UNSUPPORTED")
            result.append(
                {
                    "start": start,
                    "end": end,
                    "sha256": digest(piece.encode()),
                    "vector": self.vector(piece),
                }
            )
            if len(result) > 512:
                raise WorkbenchError("ENCODER_CHUNK_LIMIT")
            if end_token == len(offsets):
                break
            start_token = max(start_token + 1, end_token - self.manifest.overlap_tokens)
        return result


def main():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT,) * 2)
        manifest, text, operation = parse_packet(sys.stdin.buffer.read(MAX_PACKET_BYTES + 1))
        runtime = Runtime(manifest)
        if operation == "chunks":
            results = runtime.chunks(text)
        elif operation in {"query", "document"}:
            results = [{"vector": runtime.vector(text, query=operation == "query")}]
        data = json.dumps(
            {"encoder_id": manifest.identity(), "results": results}, allow_nan=False
        ).encode()
        if len(data) > MAX_RESULT:
            raise WorkbenchError("ENCODER_RESULT_LIMIT")
        sys.stdout.buffer.write(data)
    except WorkbenchError as exc:
        sys.stdout.write(json.dumps({"error": exc.code}))
        raise SystemExit(1) from None
    except Exception:
        sys.stdout.write(json.dumps({"error": "ENCODER_UNAVAILABLE"}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
