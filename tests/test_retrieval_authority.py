"""Column ACLs are observed through the actual restricted writer connection."""

import os

import psycopg
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OW_TEST_RETRIEVAL") != "1", reason="optional retrieval fixture not enabled"
    ),
]


def test_writer_update_allowlist_is_exact(databases):
    with databases[0].connect() as conn:
        rows = conn.execute("""SELECT c.relname,a.attname FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          WHERE n.nspname='ow' AND c.relname IN ('retrieval_generations','retrieval_active')
            AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')""").fetchall()
    assert {(r["relname"], r["attname"]) for r in rows} == {
        ("retrieval_generations", "status"),
        ("retrieval_generations", "error_code"),
        ("retrieval_active", "generation_id"),
    }


@pytest.mark.parametrize(
    "query",
    [
        "UPDATE ow.retrieval_generations SET corpus_sha256=repeat('0',64)",
        "UPDATE ow.retrieval_generations SET space_id=repeat('0',64)",
        "UPDATE ow.retrieval_generations SET generation_id=gen_random_uuid()",
        "UPDATE ow.retrieval_generations SET dimensions=1",
        "UPDATE ow.retrieval_generations SET created_at=clock_timestamp()",
        "UPDATE ow.retrieval_active SET singleton=false",
    ],
)
def test_writer_cannot_rewrite_retrieval_identity(databases, query):
    with pytest.raises(psycopg.errors.InsufficientPrivilege), databases[0].connect() as conn:
        conn.execute(query)
