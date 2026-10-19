"""Native schema and commit-acknowledgement fault boundaries for SQL purge."""

from contextlib import contextmanager

import psycopg
import pytest

from osint_workbench import record_purge
from osint_workbench.errors import WorkbenchError
from tests.test_record_purge import context as context
from tests.test_record_purge import plan, retired_document, state

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "customization",
    [
        "column",
        "rule",
        "widened-ledger-trigger",
        "extra-ledger-trigger",
        "widened-review-trigger",
        "extra-review-trigger",
    ],
)
def test_unreviewed_column_or_rewrite_rule_refused_before_mutation(context, customization):
    document = retired_document(context)
    path, receipt = plan(context, document)
    with context["admin"].connect() as conn:
        if customization == "column":
            conn.execute("ALTER TABLE ow.chunks ADD COLUMN synthetic_reference text")
        elif customization == "widened-ledger-trigger":
            # The reviewed name no longer implies the reviewed UPDATE-only timing.
            conn.execute(
                "DROP TRIGGER remote_operation_transition ON ow.remote_operations;"
                "CREATE TRIGGER remote_operation_transition BEFORE UPDATE OR DELETE "
                "ON ow.remote_operations FOR EACH ROW "
                "EXECUTE FUNCTION ow.remote_operation_transition()"
            )
        elif customization == "extra-ledger-trigger":
            conn.execute(
                "CREATE TRIGGER synthetic_extra BEFORE UPDATE ON ow.remote_operations "
                "FOR EACH ROW EXECUTE FUNCTION ow.remote_operation_transition()"
            )
        elif customization == "widened-review-trigger":
            conn.execute(
                "DROP TRIGGER authenticate_review ON ow.assertion_reviews;"
                "CREATE TRIGGER authenticate_review BEFORE INSERT OR DELETE "
                "ON ow.assertion_reviews FOR EACH ROW EXECUTE FUNCTION ow.authenticate_review()"
            )
        elif customization == "extra-review-trigger":
            conn.execute(
                "CREATE TRIGGER synthetic_extra BEFORE INSERT ON ow.assertion_reviews "
                "FOR EACH ROW EXECUTE FUNCTION ow.authenticate_review()"
            )
        else:
            conn.execute(
                "CREATE RULE synthetic_extra_write AS ON DELETE TO ow.chunks "
                "DO ALSO INSERT INTO ow.sources(source_id) SELECT 'rule-canary' WHERE false"
            )
    try:
        before = state(context)
        with pytest.raises(WorkbenchError):
            plan(context, document, name="rejected.owpurge")
        with pytest.raises(WorkbenchError):
            record_purge.apply(context["purger"], path, receipt["sha256"])
        assert state(context) == before
    finally:
        with context["admin"].connect() as conn:
            if customization == "column":
                conn.execute("ALTER TABLE ow.chunks DROP COLUMN synthetic_reference")
            elif customization == "widened-ledger-trigger":
                conn.execute(
                    "DROP TRIGGER remote_operation_transition ON ow.remote_operations;"
                    "CREATE TRIGGER remote_operation_transition BEFORE UPDATE "
                    "ON ow.remote_operations FOR EACH ROW "
                    "EXECUTE FUNCTION ow.remote_operation_transition()"
                )
            elif customization == "extra-ledger-trigger":
                conn.execute("DROP TRIGGER synthetic_extra ON ow.remote_operations")
            elif customization == "widened-review-trigger":
                conn.execute(
                    "DROP TRIGGER authenticate_review ON ow.assertion_reviews;"
                    "CREATE TRIGGER authenticate_review BEFORE INSERT "
                    "ON ow.assertion_reviews FOR EACH ROW EXECUTE FUNCTION ow.authenticate_review()"
                )
            elif customization == "extra-review-trigger":
                conn.execute("DROP TRIGGER synthetic_extra ON ow.assertion_reviews")
            else:
                conn.execute("DROP RULE synthetic_extra_write ON ow.chunks")


def test_actual_commit_then_injected_acknowledgement_failure_reconciles_from_event(context):
    document = retired_document(context)
    path, receipt = plan(context, document)

    class LostAcknowledgement:
        @contextmanager
        def connect(self, **kwargs):
            with context["purger"].connect(**kwargs) as conn:
                yield conn
            # The real SQL transaction has committed and the real connection closed.
            # Inject only loss of acknowledgement; this is not a wire-disconnect test.
            raise psycopg.OperationalError("synthetic post-commit acknowledgement fault")

    with pytest.raises(psycopg.OperationalError):
        record_purge.apply(LostAcknowledgement(), path, receipt["sha256"])
    with context["admin"].connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)
        ).fetchone()
        assert conn.execute(
            "SELECT 1 FROM ow.lifecycle_events WHERE operation_id=%s AND action='purge'",
            (receipt_operation(path),),
        ).fetchone()
    result = record_purge.apply(context["purger"], path, receipt["sha256"])
    assert result["replayed"] and result["sql_deleted"]


def receipt_operation(path):
    import json

    return json.loads(path.read_bytes())["payload"]["request"]["operation_id"]


def test_core_only_dataset_purges_without_optional_retrieval(context):
    import uuid

    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from osint_workbench import lifecycle
    from osint_workbench.database import Database
    from osint_workbench.evidence import EvidenceStore
    from tests.test_recovery import _input, isolated

    with isolated(context["roles"], retrieval=False) as target:
        store = EvidenceStore(context["tmp"] / "core-only-objects")
        writer = Database(target["writer"])
        document = writer.ingest(_input(), b"synthetic core-only raw", store)
        lifecycle.apply(
            Database(target["lifecycle"]),
            lifecycle.Change(
                action="retire",
                document_id=document,
                operation_id=uuid.uuid4().hex,
                actor="synthetic-operator",
                rationale="Core-only boundary acceptance",
            ),
        )
        purger = Database(
            make_conninfo(
                context["purger"]._dsn, dbname=conninfo_to_dict(target["admin"])["dbname"]
            )
        )
        path = context["tmp"] / "core-only.owpurge"
        planned = record_purge.plan(
            purger,
            path,
            document_id=document,
            operation_id=uuid.uuid4().hex,
            actor="synthetic-operator",
            rationale="Core-only SQL deletion",
        )
        result = record_purge.apply(purger, path, planned["sha256"])
        assert result["counts"]["documents"] == 1
        assert result["counts"]["retrieval_vectors"] == 0
        assert record_purge.apply(purger, path, planned["sha256"])["replayed"]
        with writer.connect() as conn:
            assert not conn.execute("SELECT 1 FROM ow.documents").fetchone()
