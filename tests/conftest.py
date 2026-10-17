import hashlib
import json
import os
import secrets
import uuid
from importlib.resources import files

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb

from osint_workbench.database import Database, migrate
from osint_workbench.evidence import EvidenceStore
from osint_workbench.service import ReadService


def pytest_addoption(parser):
    parser.addoption("--require-integration", action="store_true", default=False)


def pytest_configure(config):
    if config.getoption("--require-integration") and not os.environ.get("OW_TEST_ADMIN_DSN"):
        raise pytest.UsageError("OW_TEST_ADMIN_DSN is required; missing integration is not a pass")


@pytest.fixture(scope="session")
def roles(tmp_path_factory):
    dsn = os.environ.get("OW_TEST_ADMIN_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL unavailable; integration NOT VERIFIED locally")
    legacy_store = EvidenceStore(tmp_path_factory.mktemp("legacy-evidence"))
    legacy_body = "Legacy storage evidence."
    raw_sha = legacy_store.put(b"synthetic legacy raw")
    text_sha = legacy_store.put(legacy_body.encode())
    external = hashlib.sha256(b"legacy").hexdigest()
    snapshot = hashlib.sha256(
        json.dumps(["upgrade-fixture", raw_sha, text_sha, "text/1"]).encode()
    ).hexdigest()
    document = hashlib.sha256(
        json.dumps(["upgrade-fixture", external, snapshot, "Legacy", None]).encode()
    ).hexdigest()
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
            conn.execute(
                "INSERT INTO ow.snapshots(snapshot_id,source_id,raw_sha256,text_sha256,extractor) "
                "VALUES (%s,'upgrade-fixture',%s,%s,'text/1')",
                (snapshot, raw_sha, text_sha),
            )
            conn.execute(
                "INSERT INTO ow.documents(document_id,source_id,external_key,"
                "snapshot_id,title,body) "
                "VALUES (%s,'upgrade-fixture',%s,%s,'Legacy',%s)",
                (document, external, snapshot, legacy_body),
            )
            conn.execute(
                "INSERT INTO ow.document_heads VALUES ('upgrade-fixture',%s,%s)",
                (external, document),
            )
    # Pause at the exact published v4 schema and retain a real collection record
    # before applying the new scheduling migration.
    with psycopg.connect(dsn) as conn:
        for version, name in enumerate(
            (
                "migrations/002_workflows.sql",
                "migrations/003_intelligence.sql",
                "migrations/004_lifecycle.sql",
            ),
            2,
        ):
            if not conn.execute(
                "SELECT 1 FROM ow.migrations WHERE version=%s", (version,)
            ).fetchone():
                script = files("osint_workbench").joinpath(name).read_text()
                conn.execute(script)
                conn.execute(
                    "INSERT INTO ow.migrations(version,sha256) VALUES (%s,%s)",
                    (version, hashlib.sha256(script.encode()).hexdigest()),
                )
        if (
            conn.execute("SELECT 1 FROM ow.sources WHERE source_id='upgrade-fixture'").fetchone()
            and not conn.execute("SELECT 1 FROM ow.migrations WHERE version=5").fetchone()
        ):
            conn.execute(
                "INSERT INTO ow.collection_runs(run_id,source_id,status,raw_sha256) "
                "VALUES (gen_random_uuid(),'upgrade-fixture','succeeded',%s)",
                (raw_sha,),
            )
    migrate(dsn)
    with psycopg.connect(dsn) as conn:
        if conn.execute("SELECT 1 FROM ow.sources WHERE source_id='upgrade-fixture'").fetchone():
            assert conn.execute(
                "SELECT http_status FROM ow.collection_runs WHERE source_id='upgrade-fixture'"
            ).fetchone() == (None,)
            assert not conn.execute(
                "SELECT 1 FROM ow.collection_state WHERE source_id='upgrade-fixture'"
            ).fetchone()
    with psycopg.connect(dsn) as conn:
        if conn.execute("SELECT 1 FROM ow.sources WHERE source_id='upgrade-fixture'").fetchone():
            assert conn.execute(
                "SELECT status,attempt,max_attempts FROM ow.jobs WHERE kind='upgrade-fixture'"
            ).fetchone() == ("ready", 2, 5)
            if conn.execute(
                "SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)
            ).fetchone():
                assert conn.execute(
                    "SELECT retention_class,retain_until FROM ow.lifecycle_items "
                    "WHERE source_id='upgrade-fixture' AND external_key=%s",
                    (external,),
                ).fetchone() == ("manual", None)
    if os.environ.get("OW_TEST_RETRIEVAL") == "1":
        from osint_workbench.vector_index import migrate_retrieval

        # Populate the published v1 profile before the real profile-v2 upgrader.
        # The authored vector is a migration fixture, not a model-quality result.
        with psycopg.connect(dsn) as conn:
            if conn.execute("SELECT to_regclass('ow.retrieval_migrations')").fetchone()[0] is None:
                script = files("osint_workbench").joinpath("retrieval.sql").read_text()
                conn.execute(script)
                conn.execute(
                    "INSERT INTO ow.retrieval_migrations VALUES (1,%s)",
                    (hashlib.sha256(script.encode()).hexdigest(),),
                )
                if conn.execute(
                    "SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)
                ).fetchone():
                    space = hashlib.sha256(b"synthetic legacy space").hexdigest()
                    generation = uuid.uuid4()
                    corpus = hashlib.sha256(json.dumps([document]).encode()).hexdigest()
                    conn.execute(
                        "INSERT INTO ow.embedding_spaces VALUES (%s,%s,3)",
                        (space, Jsonb({"fixture": "migration-only"})),
                    )
                    conn.execute(
                        "INSERT INTO ow.retrieval_generations(generation_id,space_id,dimensions,"
                        "corpus_sha256,status) VALUES (%s,%s,3,%s,'ready')",
                        (generation, space, corpus),
                    )
                    conn.execute(
                        "INSERT INTO ow.retrieval_members VALUES (%s,%s)", (generation, document)
                    )
                    conn.execute(
                        "INSERT INTO ow.retrieval_vectors VALUES (%s,%s,3,%s,0,0,%s,%s,"
                        "'[1,0,0]'::ow_vector.vector)",
                        (generation, space, document, len(legacy_body), text_sha),
                    )
                    conn.execute("INSERT INTO ow.retrieval_active VALUES (true,%s)", (generation,))
            prior_generation = conn.execute(
                "SELECT g.generation_id,g.space_id,g.status,g.corpus_sha256 "
                "FROM ow.retrieval_active a JOIN ow.retrieval_generations g "
                "USING(generation_id)"
            ).fetchone()
        migrate_retrieval(dsn)
        with psycopg.connect(dsn) as conn:
            assert (
                conn.execute(
                    "SELECT g.generation_id,g.space_id,g.status,g.corpus_sha256 "
                    "FROM ow.retrieval_active a JOIN ow.retrieval_generations g "
                    "USING(generation_id)"
                ).fetchone()
                == prior_generation
            )
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
    values = {
        "admin": dsn,
        "writer": make_conninfo(dsn, user="ow_test_writer", password=writer_password),
        "reader": make_conninfo(dsn, user="ow_test_reader", password=reader_password),
        "lifecycle": make_conninfo(dsn, user="ow_test_lifecycle", password=writer_password),
    }
    with psycopg.connect(dsn) as conn:
        has_legacy = bool(
            conn.execute("SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)).fetchone()
        )
    if has_legacy:
        reader = Database(values["reader"])
        service = ReadService(reader, EvidenceStore(legacy_store.root, read_only=True))
        assert service.document(document)["integrity"] == "verified"
        assert service.evidence(snapshot)["integrity"] == "verified"
        if os.environ.get("OW_TEST_RETRIEVAL") == "1":
            with reader.connect() as conn:
                assert (
                    conn.execute(
                        "SELECT document_id FROM ow.visible_retrieval_vectors WHERE document_id=%s",
                        (document,),
                    ).fetchone()["document_id"]
                    == document
                )
    return values


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
                "ow.collection_state,ow.collection_runs,ow.job_events,ow.chunks,ow.jobs,ow.document_heads,"
                "ow.documents,ow.snapshots,ow.sources"
            )
            return Database(roles["writer"]), Database(roles["reader"]), roles
        conn.execute(
            "TRUNCATE ow.briefings,ow.assertion_reviews,ow.assertions,ow.enrichments,"
            "ow.collection_state,ow.collection_runs,ow.job_events,ow.chunks,ow.jobs,ow.document_heads,"
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
