"""Generate synthetic constant GGUF weights for native execution tests, never semantic use."""


def make_model(path):
    import gguf
    import numpy as np

    # SentencePiece vocabulary with byte fallback; every output byte is representable.
    tokens = ["<unk>", "<s>", "</s>"] + [f"<0x{i:02X}>" for i in range(256)] + ["▁"]
    vocab = len(tokens)
    writer = gguf.GGUFWriter(path, "llama")
    writer.add_name("synthetic-constant-llama")
    writer.add_context_length(4096)
    writer.add_embedding_length(32)
    writer.add_feed_forward_length(64)
    writer.add_block_count(1)
    writer.add_head_count(4)
    writer.add_head_count_kv(4)
    writer.add_rope_dimension_count(8)
    writer.add_layer_norm_rms_eps(1e-5)
    writer.add_tokenizer_model("llama")
    writer.add_token_list(tokens)
    writer.add_token_scores([0.0] * vocab)
    writer.add_token_types([2, 3, 3] + [6] * 256 + [1])
    writer.add_unk_token_id(0)
    writer.add_bos_token_id(1)
    writer.add_eos_token_id(2)
    writer.add_add_bos_token(True)
    writer.add_add_eos_token(False)
    for name, shape in {
        "token_embd.weight": (vocab, 32),
        "output.weight": (vocab, 32),
        "blk.0.attn_q.weight": (32, 32),
        "blk.0.attn_k.weight": (32, 32),
        "blk.0.attn_v.weight": (32, 32),
        "blk.0.attn_output.weight": (32, 32),
        "blk.0.ffn_gate.weight": (64, 32),
        "blk.0.ffn_up.weight": (64, 32),
        "blk.0.ffn_down.weight": (32, 64),
    }.items():
        value = np.zeros(shape, dtype=np.float32)
        if name == "token_embd.weight":
            value[:] = 0.1
        elif name == "output.weight":
            value[:] = 0.1
            value[2] = 1.0
            for byte in [9, 10, 13, 32]:
                value[byte + 3] = -1.0
            value[-1] = -1.0
        writer.add_tensor(name, value)
    for name in ["output_norm.weight", "blk.0.attn_norm.weight", "blk.0.ffn_norm.weight"]:
        writer.add_tensor(name, np.ones(32, dtype=np.float32))
    writer.write_header_to_file()
    writer.write_kv_data_to_file()
    writer.write_tensors_to_file()
    writer.close()
