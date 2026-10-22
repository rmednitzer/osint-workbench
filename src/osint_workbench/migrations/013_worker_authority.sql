-- Runtime services never inherit the operator's generic producer capability.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_chunk_worker') THEN
    CREATE ROLE ow_chunk_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_local_enricher') THEN
    CREATE ROLE ow_local_enricher NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_dispatcher') THEN
    CREATE ROLE ow_dispatcher NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
-- Deployment authority, independently reprovisioned on recovery, not dataset data.
CREATE TABLE ow.worker_kinds (
  database_principal name PRIMARY KEY,
  kind text NOT NULL CHECK (kind ~ '^document.enrich/[0-9a-f]{64}$'),
  execution_class text NOT NULL CHECK (execution_class IN ('local','remote'))
);
GRANT USAGE ON SCHEMA ow TO ow_chunk_worker,ow_local_enricher,ow_dispatcher;
GRANT SELECT ON ow.worker_kinds,ow.jobs,ow.job_events,ow.visible_documents,
  ow.visible_snapshots,ow.active_documents,ow.lifecycle_items,ow.lifecycle_tombstones
  TO ow_chunk_worker,ow_local_enricher,ow_dispatcher;
GRANT SELECT,INSERT ON ow.chunks TO ow_chunk_worker;
GRANT SELECT,INSERT ON ow.enrichments,ow.assertions TO ow_local_enricher,ow_dispatcher;
GRANT INSERT ON ow.job_events TO ow_chunk_worker,ow_local_enricher,ow_dispatcher;
GRANT USAGE ON SEQUENCE ow.job_events_event_id_seq
  TO ow_chunk_worker,ow_local_enricher,ow_dispatcher;
GRANT INSERT(job_id,kind,dedup_key,payload),
  UPDATE(status,attempt,fence,lease_until,result,available_at,last_error,updated_at,dedup_key)
  ON ow.jobs TO ow_chunk_worker;
GRANT UPDATE(status,attempt,fence,lease_until,result,available_at,last_error,updated_at)
  ON ow.jobs TO ow_local_enricher,ow_dispatcher;
ALTER TABLE ow.jobs ADD COLUMN claimed_by name;
ALTER TABLE ow.remote_operations ADD COLUMN database_principal name;
-- Historical operations have no authenticated owner and cannot be rewritten by
-- a runtime dispatcher. Accounting/recovery retain their independent authority.
GRANT SELECT ON ow.remote_operations TO ow_dispatcher;
GRANT INSERT(attempt_id,operation_id,route_id,policy_sha256,task,data_class,decision,reason,
  packet_sha256,currency,reserved,status),
  UPDATE(status,input_tokens,output_tokens,usage,estimated_cost,response_sha256,error_code)
  ON ow.remote_operations TO ow_dispatcher;

CREATE FUNCTION ow.guard_worker_job() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE runtime boolean; allowed boolean;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
     OR current_user=(SELECT pg_get_userbyid(relowner) FROM pg_class
                     WHERE oid='ow.jobs'::regclass) THEN RETURN NEW; END IF;
  runtime := pg_has_role(session_user,'ow_chunk_worker','MEMBER')
    OR pg_has_role(session_user,'ow_local_enricher','MEMBER')
    OR pg_has_role(session_user,'ow_dispatcher','MEMBER');
  IF NOT runtime THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN
    IF NOT pg_has_role(session_user,'ow_chunk_worker','MEMBER')
       OR NEW.kind<>'document.chunked' OR NEW.status<>'ready' OR NEW.attempt<>0
       OR NEW.fence IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.result IS NOT NULL
    THEN RAISE EXCEPTION 'worker job insertion refused' USING ERRCODE='insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  -- The enqueue helper locks an existing downstream receipt with an exact
  -- no-op UPSERT. It may never reset even a terminal receipt.
  IF pg_has_role(session_user,'ow_chunk_worker','MEMBER')
     AND OLD.kind='document.chunked' AND to_jsonb(NEW)=to_jsonb(OLD) THEN RETURN NEW; END IF;
  allowed := (pg_has_role(session_user,'ow_chunk_worker','MEMBER')
                 AND OLD.kind='document.accepted') OR EXISTS (
    SELECT 1 FROM ow.worker_kinds k WHERE k.database_principal=session_user AND k.kind=OLD.kind
      AND ((k.execution_class='local' AND pg_has_role(session_user,'ow_local_enricher','MEMBER'))
        OR (k.execution_class='remote' AND pg_has_role(session_user,'ow_dispatcher','MEMBER'))));
  IF NOT allowed OR ROW(NEW.job_id,NEW.kind,NEW.dedup_key,NEW.payload,NEW.created_at,NEW.max_attempts)
       IS DISTINCT FROM ROW(OLD.job_id,OLD.kind,OLD.dedup_key,OLD.payload,OLD.created_at,OLD.max_attempts)
     OR OLD.status IN ('succeeded','failed','cancelled') OR NEW.status='cancelled'
  THEN RAISE EXCEPTION 'worker job mutation refused' USING ERRCODE='insufficient_privilege';
  END IF;
  IF NEW.status='running' AND NEW.fence IS DISTINCT FROM OLD.fence THEN
    IF NOT ((OLD.status='ready' AND OLD.available_at<=clock_timestamp())
         OR (OLD.status='running' AND OLD.lease_until<=clock_timestamp()))
       OR NEW.attempt<>OLD.attempt+1 OR NEW.fence IS NULL
       OR NEW.lease_until<=clock_timestamp()
    THEN RAISE EXCEPTION 'invalid worker claim' USING ERRCODE='check_violation'; END IF;
    NEW.claimed_by := session_user;
  ELSIF NEW.status='failed' AND OLD.attempt>=OLD.max_attempts
        AND (OLD.status='ready' OR OLD.lease_until<=clock_timestamp())
        AND NEW.fence IS NULL AND NEW.lease_until IS NULL THEN
    NULL; -- bounded reaping of exhausted work, without accepting its result
  ELSIF OLD.status='running' THEN
    IF OLD.claimed_by IS DISTINCT FROM session_user OR OLD.lease_until<=clock_timestamp()
       OR NEW.attempt<>OLD.attempt
       OR (NEW.status IN ('running','succeeded') AND NEW.fence IS DISTINCT FROM OLD.fence)
    THEN RAISE EXCEPTION 'worker lease not owned' USING ERRCODE='insufficient_privilege'; END IF;
  ELSIF NOT (NEW.status='failed' AND OLD.attempt>=OLD.max_attempts) THEN
    RAISE EXCEPTION 'invalid worker transition' USING ERRCODE='check_violation';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ow.guard_worker_job() FROM PUBLIC;
CREATE TRIGGER guard_worker_job BEFORE INSERT OR UPDATE ON ow.jobs
  FOR EACH ROW EXECUTE FUNCTION ow.guard_worker_job();

CREATE FUNCTION ow.guard_remote_owner() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
     OR current_user=(SELECT pg_get_userbyid(relowner) FROM pg_class
                     WHERE oid='ow.remote_operations'::regclass) THEN RETURN NEW; END IF;
  -- Recovery/owners are trusted; runtime and operator producer sessions are not.
  IF NOT (pg_has_role(session_user,'ow_writer','MEMBER')
          OR pg_has_role(session_user,'ow_dispatcher','MEMBER')
          OR pg_has_role(session_user,'ow_local_enricher','MEMBER')
          OR pg_has_role(session_user,'ow_chunk_worker','MEMBER')) THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN
    NEW.database_principal := session_user;
  ELSIF OLD.settlement_basis IS NOT NULL THEN
    RETURN NEW; -- the existing state machine rejects all post-settlement writes
  ELSIF OLD.database_principal IS DISTINCT FROM session_user
       OR NEW.database_principal IS DISTINCT FROM OLD.database_principal THEN
    RAISE EXCEPTION 'remote operation not owned' USING ERRCODE='insufficient_privilege';
  END IF;
  IF NEW.settlement_basis IS NOT NULL THEN
    RAISE EXCEPTION 'dispatcher cannot settle' USING ERRCODE='insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ow.guard_remote_owner() FROM PUBLIC;
CREATE TRIGGER guard_remote_owner BEFORE INSERT OR UPDATE ON ow.remote_operations
  FOR EACH ROW EXECUTE FUNCTION ow.guard_remote_owner();

-- Extend direct-SQL reviewer exclusion to the new runtime production roles.
CREATE OR REPLACE FUNCTION ow.authenticate_review() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  -- Exact owner or superuser may restore preserved provenance. They can already
  -- replace this function/data and are outside the runtime authority boundary.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
     OR current_user=(SELECT pg_get_userbyid(relowner) FROM pg_class
                     WHERE oid='ow.assertion_reviews'::regclass) THEN
    RETURN NEW;
  END IF;
  IF NOT pg_has_role(session_user,'ow_reviewer','MEMBER')
     OR NOT pg_has_role(current_user,'ow_reviewer','USAGE')
     OR pg_has_role(session_user,'ow_writer','MEMBER')
     OR pg_has_role(current_user,'ow_writer','MEMBER')
     OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
       ('ow_chunk_worker','ow_local_enricher','ow_dispatcher')
       AND (pg_has_role(session_user,oid,'MEMBER') OR pg_has_role(current_user,oid,'MEMBER'))) THEN
    RAISE EXCEPTION 'separate reviewer credential required'
      USING ERRCODE='insufficient_privilege';
  END IF;
  NEW.authority := 'authenticated_reviewer';
  NEW.database_principal := session_user;
  NEW.reviewed_at := clock_timestamp();
  RETURN NEW;
END $$;

CREATE FUNCTION ow.guard_worker_event() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE job_kind text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
     OR current_user=(SELECT pg_get_userbyid(relowner) FROM pg_class
                     WHERE oid='ow.job_events'::regclass) THEN RETURN NEW; END IF;
  IF NOT (pg_has_role(session_user,'ow_chunk_worker','MEMBER')
       OR pg_has_role(session_user,'ow_local_enricher','MEMBER')
       OR pg_has_role(session_user,'ow_dispatcher','MEMBER')) THEN RETURN NEW; END IF;
  SELECT kind INTO job_kind FROM ow.jobs WHERE job_id=NEW.job_id;
  IF (pg_has_role(session_user,'ow_chunk_worker','MEMBER')
         AND job_kind IN ('document.accepted','document.chunked')) OR EXISTS (
    SELECT 1 FROM ow.worker_kinds k WHERE k.database_principal=session_user AND k.kind=job_kind
      AND ((k.execution_class='local' AND pg_has_role(session_user,'ow_local_enricher','MEMBER'))
        OR (k.execution_class='remote' AND pg_has_role(session_user,'ow_dispatcher','MEMBER'))))
  THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'worker event scope refused' USING ERRCODE='insufficient_privilege';
END $$;
REVOKE ALL ON FUNCTION ow.guard_worker_event() FROM PUBLIC;
CREATE TRIGGER guard_worker_event BEFORE INSERT ON ow.job_events
  FOR EACH ROW EXECUTE FUNCTION ow.guard_worker_event();
