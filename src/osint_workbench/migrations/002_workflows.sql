-- Additive upgrade; schema.sql remains immutable after publication.
ALTER TABLE ow.jobs ADD COLUMN available_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE ow.jobs ADD COLUMN max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100);
ALTER TABLE ow.jobs ADD COLUMN last_error text;
ALTER TABLE ow.jobs ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE ow.jobs ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE TABLE ow.job_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  job_id uuid NOT NULL REFERENCES ow.jobs,
  attempt integer NOT NULL,
  fence uuid,
  event text NOT NULL CHECK (event IN ('claimed','expired','succeeded','retry','failed','cancelled')),
  code text,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX job_events_job ON ow.job_events(job_id,event_id);
CREATE INDEX jobs_due ON ow.jobs(kind,available_at) WHERE status IN ('ready','running');
CREATE TABLE ow.chunks (
  chunk_id text PRIMARY KEY CHECK (chunk_id ~ '^[0-9a-f]{64}$'),
  document_id text NOT NULL REFERENCES ow.documents,
  chunker text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  start_offset integer NOT NULL CHECK (start_offset >= 0),
  end_offset integer NOT NULL CHECK (end_offset > start_offset),
  text_sha256 text NOT NULL CHECK (text_sha256 ~ '^[0-9a-f]{64}$'),
  body text NOT NULL,
  CHECK (length(body)=end_offset-start_offset),
  UNIQUE(document_id,chunker,ordinal)
);
GRANT SELECT,INSERT ON ow.job_events,ow.chunks TO ow_writer;
GRANT USAGE ON SEQUENCE ow.job_events_event_id_seq TO ow_writer;
GRANT SELECT ON ow.chunks TO ow_reader;
CREATE OR REPLACE VIEW ow.pipeline_status AS
 SELECT (SELECT count(*) FROM ow.documents) AS documents,
        (SELECT count(*) FROM ow.snapshots) AS snapshots,
        (SELECT count(*) FROM ow.sources) AS sources,
        (SELECT count(*) FROM ow.jobs WHERE status='ready') AS ready_jobs,
        (SELECT count(*) FROM ow.jobs WHERE status='running') AS running_jobs,
        (SELECT count(*) FROM ow.jobs WHERE status='failed') AS failed_jobs,
        (SELECT count(*) FROM ow.jobs WHERE status='cancelled') AS cancelled_jobs,
        (SELECT count(*) FROM ow.chunks) AS chunks;
CREATE TABLE ow.collection_runs (
  run_id uuid PRIMARY KEY,
  source_id text NOT NULL REFERENCES ow.sources,
  status text NOT NULL CHECK (status IN ('running','succeeded','failed','interrupted')),
  accepted_documents integer NOT NULL DEFAULT 0 CHECK (accepted_documents >= 0),
  raw_sha256 text,
  error_code text,
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  finished_at timestamptz
);
CREATE INDEX collection_runs_source ON ow.collection_runs(source_id,started_at);
GRANT SELECT,INSERT,UPDATE ON ow.collection_runs TO ow_writer;
CREATE OR REPLACE VIEW ow.source_status AS
 SELECT source_id,enabled,last_attempt,last_success,last_error,
 CASE WHEN NOT enabled THEN 'disabled'
      WHEN last_error IS NOT NULL AND last_success IS NULL THEN 'unavailable'
      WHEN last_error IS NOT NULL THEN 'degraded'
      WHEN last_success IS NULL THEN 'unknown'
      WHEN clock_timestamp()-last_success > make_interval(secs=>freshness_seconds)
        THEN 'stale' ELSE 'fresh' END AS freshness
 FROM ow.sources;
