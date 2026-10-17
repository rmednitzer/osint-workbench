-- This migration is packaged with the wheel; it is not read from a checkout.
CREATE SCHEMA IF NOT EXISTS ow;
REVOKE ALL ON SCHEMA ow FROM PUBLIC;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_reader') THEN
    CREATE ROLE ow_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_writer') THEN
    CREATE ROLE ow_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS ow.migrations (
  version integer PRIMARY KEY, sha256 text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS ow.sources (
  source_id text PRIMARY KEY, enabled boolean NOT NULL DEFAULT true,
  freshness_seconds integer NOT NULL DEFAULT 86400 CHECK (freshness_seconds > 0),
  last_attempt timestamptz, last_success timestamptz, last_error text
);
CREATE TABLE IF NOT EXISTS ow.snapshots (
  snapshot_id text PRIMARY KEY,
  source_id text NOT NULL REFERENCES ow.sources,
  raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
  text_sha256 text NOT NULL CHECK (text_sha256 ~ '^[0-9a-f]{64}$'),
  extractor text NOT NULL, acquired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(source_id,raw_sha256,text_sha256,extractor)
);
CREATE TABLE IF NOT EXISTS ow.documents (
  document_id text PRIMARY KEY, source_id text NOT NULL REFERENCES ow.sources,
  external_key text NOT NULL, snapshot_id text NOT NULL REFERENCES ow.snapshots,
  title text NOT NULL, body text NOT NULL, published_at timestamptz,
  search_vector tsvector GENERATED ALWAYS AS
    (to_tsvector('simple',coalesce(title,'') || ' ' || body)) STORED,
  CHECK (length(body)<=1000000)
);
CREATE INDEX IF NOT EXISTS documents_fts ON ow.documents USING gin(search_vector);
CREATE TABLE IF NOT EXISTS ow.document_heads (
  source_id text NOT NULL REFERENCES ow.sources,external_key text NOT NULL,
  document_id text NOT NULL REFERENCES ow.documents,PRIMARY KEY(source_id,external_key)
);
CREATE OR REPLACE VIEW ow.active_documents AS
 SELECT d.* FROM ow.documents d JOIN ow.document_heads h USING(document_id);
CREATE TABLE IF NOT EXISTS ow.jobs (
  job_id uuid PRIMARY KEY, kind text NOT NULL, dedup_key text NOT NULL,
  payload jsonb NOT NULL, status text NOT NULL DEFAULT 'ready'
    CHECK (status IN ('ready','running','succeeded','failed','cancelled')),
  attempt integer NOT NULL DEFAULT 0, fence uuid, lease_until timestamptz,
  result jsonb, UNIQUE(kind,dedup_key)
);
CREATE INDEX IF NOT EXISTS jobs_ready ON ow.jobs(status,lease_until);
CREATE OR REPLACE VIEW ow.source_status AS
 SELECT source_id,enabled,last_attempt,last_success,last_error,
 CASE WHEN NOT enabled THEN 'disabled'
      WHEN last_success IS NULL THEN 'unknown'
      WHEN clock_timestamp()-last_success > make_interval(secs=>freshness_seconds)
        THEN 'stale' ELSE 'fresh' END AS freshness
 FROM ow.sources;
CREATE OR REPLACE VIEW ow.pipeline_status AS
 SELECT (SELECT count(*) FROM ow.documents) AS documents,
        (SELECT count(*) FROM ow.snapshots) AS snapshots,
        (SELECT count(*) FROM ow.sources) AS sources,
        (SELECT count(*) FROM ow.jobs WHERE status='ready') AS ready_jobs;
GRANT USAGE ON SCHEMA ow TO ow_reader,ow_writer;
GRANT SELECT ON ow.documents,ow.active_documents,ow.snapshots,ow.source_status,ow.pipeline_status TO ow_reader;
GRANT SELECT,INSERT,UPDATE ON ow.sources TO ow_writer;
GRANT SELECT,INSERT ON ow.snapshots,ow.documents TO ow_writer;
GRANT SELECT,INSERT,UPDATE ON ow.document_heads TO ow_writer;
GRANT SELECT,INSERT,UPDATE ON ow.jobs TO ow_writer;
