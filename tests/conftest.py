import hashlib
import os
import secrets
from importlib.resources import files

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from osint_workbench.database import Database, migrate


def pytest_addoption(parser):
    parser.addoption("--require-integration", action="store_true", default=False)


def pytest_configure(config):
    if config.getoption("--require-integration") and not os.environ.get("OW_TEST_ADMIN_DSN"):
        raise pytest.UsageError("OW_TEST_ADMIN_DSN is required; missing integration is not a pass")


@pytest.fixture(scope="session")
def roles():
    dsn = os.environ.get("OW_TEST_ADMIN_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL unavailable; integration NOT VERIFIED locally")
    with psycopg.connect(dsn, autocommit=True) as conn:
        if conn.info.dbname != "ow_test":
            raise RuntimeError("tests refuse any database not named ow_test")
        if conn.execute("SELECT to_regclass('ow.migrations')").fetchone()[0] is None:
            script = files("osint_workbench").joinpath("schema.sql").read_text()
            conn.execute(script)
            conn.execute(
                "INSERT INTO ow.migrations(version,sha256) VALUES (1,%s)",
                (hashlib.sha256(script.encode()).hexdigest(),),
            )
            conn.execute("INSERT INTO ow.sources(source_id) VALUES ('upgrade-fixture')")
            conn.execute("""INSERT INTO ow.jobs(job_id,kind,dedup_key,payload,status,attempt)
                         VALUES (gen_random_uuid(),'upgrade-fixture','legacy','{}','ready',2)""")
    migrate(dsn)
    with psycopg.connect(dsn) as conn:
        if conn.execute("SELECT 1 FROM ow.sources WHERE source_id='upgrade-fixture'").fetchone():
            assert conn.execute(
                "SELECT status,attempt,max_attempts FROM ow.jobs WHERE kind='upgrade-fixture'"
            ).fetchone() == ("ready", 2, 5)
    if os.environ.get("OW_TEST_RETRIEVAL") == "1":
        from osint_workbench.vector_index import migrate_retrieval

        migrate_retrieval(dsn)
    writer_password, reader_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as conn:
        for role, group, password in [
            ("ow_test_writer", "ow_writer", writer_password),
            ("ow_test_reader", "ow_reader", reader_password),
            ("ow_test_lifecycle", "ow_lifecycle", writer_password),
        ]:
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
            if not exists:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
            conn.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(password)
                )
            )
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), sql.Identifier(role))
            )
    return {
        "admin": dsn,
        "writer": make_conninfo(dsn, user="ow_test_writer", password=writer_password),
        "reader": make_conninfo(dsn, user="ow_test_reader", password=reader_password),
        "lifecycle": make_conninfo(dsn, user="ow_test_lifecycle", password=writer_password),
    }


@pytest.fixture
def databases(roles):
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            "TRUNCATE ow.lifecycle_events,ow.lifecycle_tombstones,"
            "ow.lifecycle_holds,ow.lifecycle_items"
        )
        conn.execute("UPDATE ow.lifecycle_control SET revision=0,dataset_id=gen_random_uuid()")
        if os.environ.get("OW_TEST_RETRIEVAL") == "1":
            conn.execute(
                "TRUNCATE ow.briefings,ow.assertion_reviews,ow.assertions,ow.enrichments,"
                "ow.retrieval_active,ow.retrieval_vectors,"
                "ow.retrieval_members,ow.retrieval_generations,ow.embedding_spaces,"
                "ow.collection_runs,ow.job_events,ow.chunks,ow.jobs,ow.document_heads,"
                "ow.documents,ow.snapshots,ow.sources"
            )
            return Database(roles["writer"]), Database(roles["reader"]), roles
        conn.execute(
            "TRUNCATE ow.briefings,ow.assertion_reviews,ow.assertions,ow.enrichments,"
            "ow.collection_runs,ow.job_events,ow.chunks,ow.jobs,ow.document_heads,"
            "ow.documents,ow.snapshots,ow.sources"
        )
    return Database(roles["writer"]), Database(roles["reader"]), roles


@pytest.fixture
def encoder_bundle(tmp_path):
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper
    from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, processors

    from osint_workbench.local_encoder import EncoderManifest, LocalEncoder
    from osint_workbench.retrieval import EmbeddingSpace
    from osint_workbench.text import digest

    # Deliberately authored fixture weights, no pretrained or operational model data.
    vocab = {
        "[UNK]": 0,
        "[CLS]": 1,
        "[SEP]": 2,
        "storage": 3,
        "disk": 4,
        "vulnerability": 5,
        "patch": 6,
        "straße": 7,
    }
    tokenizer = Tokenizer(models.WordLevel(vocab, unk_token="[UNK]"))
    tokenizer.normalizer = normalizers.Lowercase()
    tokenizer.pre_tokenizer = pre_tokenizers.Whitespace()
    tokenizer.post_processor = processors.TemplateProcessing(
        single="[CLS] $A [SEP]",
        pair="[CLS] $A [SEP] $B:1 [SEP]:1",
        special_tokens=[("[CLS]", 1), ("[SEP]", 2)],
    )
    token_bytes = tokenizer.to_str().encode()
    token_path = tmp_path / "tokenizer.json"
    token_path.write_bytes(token_bytes)
    weights = np.array(
        [[0, 0, 0], [0, 0, 0], [0, 0, 0], [1, 0, 0], [1, 0, 0], [0, 1, 0], [0, 1, 0], [0, 0, 1]],
        dtype=np.float32,
    )
    graph = helper.make_graph(
        [helper.make_node("Gather", ["weights", "input_ids"], ["tokens"], axis=0)],
        "synthetic-oracle",
        [helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, "sequence"])],
        [helper.make_tensor_value_info("tokens", TensorProto.FLOAT, [1, "sequence", 3])],
        [numpy_helper.from_array(weights, "weights")],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=10)
    onnx.checker.check_model(model)
    model_bytes = model.SerializeToString()
    model_path = tmp_path / "model.onnx"
    model_path.write_bytes(model_bytes)
    space = EmbeddingSpace(
        model_revision=digest(model_bytes),
        tokenizer_revision=digest(token_bytes),
        query_template="{text}",
        document_template="{text}",
        pooling="mean",
        dimensions=3,
        normalized=True,
        metric="cosine",
        precision="float32",
    )
    manifest = EncoderManifest(
        model_path=str(model_path),
        tokenizer_path=str(token_path),
        model_sha256=digest(model_bytes),
        tokenizer_sha256=digest(token_bytes),
        space=space,
        max_tokens=16,
        overlap_tokens=2,
        output_name="tokens",
    )
    return LocalEncoder(manifest)


@pytest.fixture
def reranker_bundle(encoder_bundle, tmp_path):
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    from osint_workbench.local_reranker import LocalReranker, RerankerManifest
    from osint_workbench.text import digest

    model = helper.make_model(
        helper.make_graph(
            [
                helper.make_node("Gather", ["weights", "input_ids"], ["values"], axis=0),
                helper.make_node("Cast", ["token_type_ids"], ["mask"], to=TensorProto.FLOAT),
                helper.make_node("Mul", ["values", "mask"], ["product"]),
                helper.make_node("ReduceSum", ["product", "axes"], ["logits"], keepdims=1),
            ],
            "pair-score-oracle",
            [
                helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, "sequence"]),
                helper.make_tensor_value_info("token_type_ids", TensorProto.INT64, [1, "sequence"]),
            ],
            [helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, 1])],
            [
                numpy_helper.from_array(
                    np.array([0, 0, 0, 1, 1, -1, -1, 0], dtype=np.float32), "weights"
                ),
                numpy_helper.from_array(np.array([1], dtype=np.int64), "axes"),
            ],
        ),
        opset_imports=[helper.make_opsetid("", 17)],
        ir_version=10,
    )
    onnx.checker.check_model(model)
    data = model.SerializeToString()
    path = tmp_path / "reranker.onnx"
    path.write_bytes(data)
    return LocalReranker(
        RerankerManifest(
            model_path=str(path),
            model_sha256=digest(data),
            tokenizer_path=encoder_bundle.manifest.tokenizer_path,
            tokenizer_sha256=encoder_bundle.manifest.tokenizer_sha256,
            max_tokens=32,
            output_name="logits",
        )
    )
