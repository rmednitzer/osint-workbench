-- Logical suppression is separate from physical erasure and preservation holds.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_lifecycle') THEN
    CREATE ROLE ow_lifecycle NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END $$;
CREATE TABLE ow.lifecycle_control (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  dataset_id uuid NOT NULL DEFAULT gen_random_uuid(),
  revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)
);
INSERT INTO ow.lifecycle_control DEFAULT VALUES;
ALTER TABLE ow.collection_runs ADD COLUMN suppressed_documents integer NOT NULL DEFAULT 0
 CHECK(suppressed_documents>=0);
CREATE TABLE ow.lifecycle_items (
  source_id text NOT NULL,
  external_key text NOT NULL CHECK(external_key ~ '^[0-9a-f]{64}$'),
  retention_class text NOT NULL DEFAULT 'manual' CHECK(length(retention_class) BETWEEN 1 AND 96),
  retain_until timestamptz,
  PRIMARY KEY(source_id,external_key)
);
INSERT INTO ow.lifecycle_items(source_id,external_key)
  SELECT DISTINCT source_id,external_key FROM ow.documents;
CREATE TABLE ow.lifecycle_holds (
  hold_id text PRIMARY KEY CHECK(length(hold_id) BETWEEN 1 AND 96),
  source_id text NOT NULL, external_key text NOT NULL,
  placed_at timestamptz NOT NULL DEFAULT clock_timestamp(), released_at timestamptz,
  CHECK(released_at IS NULL OR released_at>=placed_at),
  FOREIGN KEY(source_id,external_key) REFERENCES ow.lifecycle_items
);
CREATE TABLE ow.lifecycle_tombstones (
  source_id text NOT NULL, external_key text NOT NULL,
  retired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(source_id,external_key),
  FOREIGN KEY(source_id,external_key) REFERENCES ow.lifecycle_items
);
CREATE TABLE ow.lifecycle_events (
  operation_id text PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 96),
  request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
  revision bigint NOT NULL UNIQUE CHECK(revision>0),
  source_id text NOT NULL, external_key text NOT NULL,
  action text NOT NULL CHECK(action IN ('retention','hold','release','retire')),
  actor text NOT NULL CHECK(length(actor) BETWEEN 1 AND 96),
  rationale text NOT NULL CHECK(length(rationale) BETWEEN 1 AND 2000),
  result jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(source_id,external_key) REFERENCES ow.lifecycle_items
);
CREATE VIEW ow.visible_documents WITH (security_barrier=true) AS
 SELECT d.* FROM ow.documents d JOIN ow.lifecycle_items l USING(source_id,external_key)
 WHERE (l.retain_until IS NULL OR l.retain_until>statement_timestamp())
 AND NOT EXISTS (SELECT 1 FROM ow.lifecycle_tombstones t
                 WHERE t.source_id=d.source_id AND t.external_key=d.external_key);
CREATE OR REPLACE VIEW ow.active_documents WITH (security_barrier=true) AS
 SELECT d.* FROM ow.visible_documents d JOIN ow.document_heads h USING(document_id);
CREATE VIEW ow.visible_snapshots WITH (security_barrier=true) AS
 SELECT s.* FROM ow.snapshots s WHERE EXISTS
 (SELECT 1 FROM ow.visible_documents d WHERE d.snapshot_id=s.snapshot_id);
CREATE VIEW ow.visible_chunks WITH (security_barrier=true) AS
 SELECT c.* FROM ow.chunks c JOIN ow.visible_documents d USING(document_id);
CREATE VIEW ow.visible_assertions WITH (security_barrier=true) AS
 SELECT a.* FROM ow.assertions a JOIN ow.visible_documents d USING(document_id);
CREATE OR REPLACE VIEW ow.current_assertions WITH (security_barrier=true) AS
 SELECT a.*,coalesce(r.decision,'pending') AS review_state
 FROM ow.visible_assertions a JOIN ow.active_documents d USING(document_id)
 LEFT JOIN LATERAL (
   SELECT decision FROM ow.assertion_reviews r WHERE r.assertion_id=a.assertion_id
   ORDER BY review_id DESC LIMIT 1
 ) r ON true;
CREATE VIEW ow.visible_briefings WITH (security_barrier=true) AS
 SELECT b.* FROM ow.briefings b WHERE NOT EXISTS
 (SELECT 1 FROM jsonb_array_elements_text(b.content->'selected_documents') x(document_id)
  WHERE NOT EXISTS (SELECT 1 FROM ow.visible_documents d WHERE d.document_id=x.document_id));
REVOKE SELECT ON ow.documents,ow.snapshots,ow.chunks,ow.assertions,ow.briefings FROM ow_reader;
GRANT SELECT ON ow.visible_documents,ow.visible_snapshots,ow.visible_chunks,
  ow.visible_assertions,ow.visible_briefings TO ow_reader,ow_writer;
GRANT SELECT ON ow.lifecycle_items,ow.lifecycle_tombstones TO ow_writer;
GRANT INSERT(source_id,external_key) ON ow.lifecycle_items TO ow_writer;
GRANT USAGE ON SCHEMA ow TO ow_lifecycle;
GRANT SELECT ON ow.documents,ow.lifecycle_control,ow.lifecycle_items,ow.lifecycle_holds,
  ow.lifecycle_tombstones,ow.lifecycle_events,ow.jobs TO ow_lifecycle;
GRANT UPDATE ON ow.lifecycle_control,ow.lifecycle_items,ow.lifecycle_holds,ow.jobs TO ow_lifecycle;
GRANT INSERT ON ow.lifecycle_holds,ow.lifecycle_tombstones,ow.lifecycle_events,ow.job_events
  TO ow_lifecycle;
GRANT USAGE ON SEQUENCE ow.job_events_event_id_seq TO ow_lifecycle;
CREATE VIEW ow.schema_status AS SELECT max(version) AS version FROM ow.migrations;
CREATE VIEW ow.lifecycle_status AS SELECT
 (SELECT count(*) FROM ow.visible_documents) AS visible_documents,
 (SELECT count(*) FROM ow.lifecycle_tombstones) AS retired_items,
 (SELECT count(*) FROM ow.lifecycle_items WHERE retain_until<=statement_timestamp()) AS expired_items,
 (SELECT count(*) FROM ow.lifecycle_holds WHERE released_at IS NULL) AS active_holds,
 (SELECT revision FROM ow.lifecycle_control) AS policy_revision;
GRANT SELECT ON ow.schema_status,ow.lifecycle_status TO ow_reader,ow_writer;
