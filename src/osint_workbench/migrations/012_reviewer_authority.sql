-- Credential separation, not proof of a different human. Owners/recovery remain trusted.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_reviewer') THEN
    CREATE ROLE ow_reviewer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOBYPASSRLS NOREPLICATION;
  END IF;
END $$;
ALTER TABLE ow.assertion_reviews
  ADD COLUMN authority text NOT NULL DEFAULT 'legacy_writer'
    CHECK (authority IN ('legacy_writer','authenticated_reviewer')),
  ADD COLUMN database_principal text,
  ADD CONSTRAINT assertion_review_provenance CHECK (
    (authority='legacy_writer' AND database_principal IS NULL) OR
    (authority='authenticated_reviewer' AND database_principal IS NOT NULL
      AND length(database_principal) BETWEEN 1 AND 63));
CREATE FUNCTION ow.authenticate_review() RETURNS trigger
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
     OR pg_has_role(current_user,'ow_writer','MEMBER') THEN
    RAISE EXCEPTION 'separate reviewer credential required'
      USING ERRCODE='insufficient_privilege';
  END IF;
  NEW.authority := 'authenticated_reviewer';
  NEW.database_principal := session_user;
  NEW.reviewed_at := clock_timestamp();
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ow.authenticate_review() FROM PUBLIC;
CREATE TRIGGER authenticate_review BEFORE INSERT ON ow.assertion_reviews
  FOR EACH ROW EXECUTE FUNCTION ow.authenticate_review();
REVOKE INSERT ON ow.assertion_reviews FROM ow_writer;
REVOKE USAGE ON SEQUENCE ow.assertion_reviews_review_id_seq FROM ow_writer;
GRANT USAGE ON SCHEMA ow TO ow_reviewer;
GRANT SELECT ON ow.current_assertions TO ow_reviewer;
GRANT INSERT(assertion_id,decision,actor,rationale) ON ow.assertion_reviews TO ow_reviewer;
GRANT USAGE ON SEQUENCE ow.assertion_reviews_review_id_seq TO ow_reviewer;
CREATE OR REPLACE VIEW ow.current_assertions WITH (security_barrier=true) AS
 SELECT a.*,coalesce(r.decision,'pending') AS review_state
 FROM ow.visible_assertions a JOIN ow.active_documents d USING(document_id)
 LEFT JOIN LATERAL (
   SELECT decision FROM ow.assertion_reviews r WHERE r.assertion_id=a.assertion_id
     AND r.authority='authenticated_reviewer'
   ORDER BY review_id DESC LIMIT 1
 ) r ON true;
