-- Additive core migration 10: operator settlement of remote attempts.
-- A settlement replaces conservative exposure with an evidence-bound amount. It
-- lives on the attempt row so the row lock and the transition trigger serialize
-- it against a late worker outcome, whatever the session isolation level.
-- Owners and superusers can bypass triggers; they are outside this contract.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_accounting') THEN
    CREATE ROLE ow_accounting NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOBYPASSRLS NOREPLICATION;
  END IF;
END $$;
ALTER TABLE ow.remote_operations
  ADD COLUMN settlement_basis text CHECK (settlement_basis IN
    ('invoice','usage_export','provider_statement','not_dispatched')),
  ADD COLUMN settled_cost numeric(15,9) CHECK (settled_cost >= 0),
  ADD COLUMN settlement_evidence_sha256 text
    CHECK (settlement_evidence_sha256 ~ '^[0-9a-f]{64}$'),
  ADD COLUMN settled_by text CHECK (length(settled_by) BETWEEN 1 AND 96),
  ADD COLUMN settlement_rationale text
    CHECK (length(settlement_rationale) BETWEEN 1 AND 2000),
  ADD COLUMN settled_at timestamptz,
  ADD CONSTRAINT remote_operations_settlement_complete CHECK (
    (settlement_basis IS NULL) = (settled_cost IS NULL)
    AND (settlement_basis IS NULL) = (settled_by IS NULL)
    AND (settlement_basis IS NULL) = (settlement_rationale IS NULL)
    AND (settlement_basis IS NULL) = (settled_at IS NULL)),
  ADD CONSTRAINT remote_operations_settlement_scope CHECK (
    settlement_basis IS NULL OR status NOT IN ('denied','released')),
  -- Only a never-dispatched reservation is settled without provider evidence.
  ADD CONSTRAINT remote_operations_settlement_evidence CHECK (
    settlement_basis IS NULL
    OR (settlement_basis = 'not_dispatched' AND status = 'reserved' AND settled_cost = 0
        AND settlement_evidence_sha256 IS NULL)
    OR (settlement_basis <> 'not_dispatched' AND settlement_evidence_sha256 IS NOT NULL));
CREATE OR REPLACE FUNCTION ow.remote_operation_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- A settled attempt is final: no late outcome, dispatch or second settlement.
  IF OLD.settlement_basis IS NOT NULL THEN
    RAISE EXCEPTION 'settled remote operation is immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.settlement_basis IS NOT NULL THEN
    -- The identity that spends never settles, including through SET ROLE.
    IF pg_has_role(session_user, 'ow_writer', 'MEMBER')
       OR pg_has_role(current_user, 'ow_writer', 'MEMBER') THEN
      RAISE EXCEPTION 'writer cannot settle remote operations'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Settlement changes only its own columns, whatever grants exist.
    IF (to_jsonb(NEW) - '{settlement_basis,settled_cost,settlement_evidence_sha256,settled_by,settlement_rationale,settled_at}'::text[])
       IS DISTINCT FROM
       (to_jsonb(OLD) - '{settlement_basis,settled_cost,settlement_evidence_sha256,settled_by,settlement_rationale,settled_at}'::text[])
       -- Reserved and dispatched rows may still belong to a live worker whose
       -- request deadline is at most 120 seconds.
       OR (OLD.status IN ('reserved','dispatched')
           AND OLD.updated_at > clock_timestamp() - interval '10 minutes')
    THEN
      RAISE EXCEPTION 'invalid remote operation settlement' USING ERRCODE = 'check_violation';
    END IF;
    NEW.settled_at := clock_timestamp();
    RETURN NEW;
  END IF;
  IF NOT ((OLD.status = 'reserved' AND NEW.status = 'dispatched')
      OR (OLD.status = 'dispatched' AND NEW.status IN
          ('released','completed','refused','incomplete','failed','outcome_unknown')))
     OR (OLD.status = 'reserved' AND (NEW.usage IS NOT NULL OR NEW.estimated_cost IS NOT NULL
         OR NEW.response_sha256 IS NOT NULL))
     OR (NEW.status = 'released' AND (NEW.usage IS NOT NULL OR NEW.response_sha256 IS NOT NULL))
  THEN
    RAISE EXCEPTION 'invalid remote operation transition' USING ERRCODE = 'check_violation';
  END IF;
  -- The in-flight window is measured from a database time the writer cannot set.
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ow.remote_operation_transition() FROM PUBLIC;
-- The writer records attempts and outcomes; it can no longer insert settlement,
-- timestamp or other unlisted columns, and it never settles its own exposure.
REVOKE INSERT ON ow.remote_operations FROM ow_writer;
REVOKE UPDATE(updated_at) ON ow.remote_operations FROM ow_writer;
GRANT INSERT(attempt_id,operation_id,route_id,policy_sha256,task,data_class,decision,reason,
  packet_sha256,currency,reserved,status) ON ow.remote_operations TO ow_writer;
GRANT USAGE ON SCHEMA ow TO ow_accounting;
GRANT SELECT ON ow.remote_operations TO ow_accounting;
GRANT UPDATE(settlement_basis,settled_cost,settlement_evidence_sha256,settled_by,
  settlement_rationale) ON ow.remote_operations TO ow_accounting;
