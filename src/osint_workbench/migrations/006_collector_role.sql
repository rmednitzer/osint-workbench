-- Additive authority boundary; existing writer grants and published migrations remain unchanged.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_collector') THEN
    CREATE ROLE ow_collector NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
ALTER TABLE ow.jobs ALTER COLUMN kind SET DEFAULT 'document.accepted';
GRANT USAGE ON SCHEMA ow TO ow_collector;
GRANT SELECT(version,sha256) ON ow.migrations TO ow_collector;
GRANT INSERT(source_id,enabled,freshness_seconds),
      SELECT(source_id,enabled,freshness_seconds),
      UPDATE(enabled,freshness_seconds,last_attempt,last_success,last_error)
 ON ow.sources TO ow_collector;
GRANT INSERT(snapshot_id,source_id,raw_sha256,text_sha256,extractor)
 ON ow.snapshots TO ow_collector;
GRANT INSERT(document_id,source_id,external_key,snapshot_id,title,body,published_at),
      SELECT(document_id) ON ow.documents TO ow_collector;
GRANT INSERT(source_id,external_key,document_id),
      SELECT(source_id,external_key,document_id),UPDATE(document_id)
 ON ow.document_heads TO ow_collector;
-- Omitting kind is mandatory: a collector cannot choose another worker's job kind.
GRANT INSERT(job_id,dedup_key,payload) ON ow.jobs TO ow_collector;
GRANT INSERT(source_id,external_key),SELECT(source_id,external_key,retain_until)
 ON ow.lifecycle_items TO ow_collector;
GRANT SELECT(source_id,external_key) ON ow.lifecycle_tombstones TO ow_collector;
GRANT INSERT(run_id,source_id,status),
      SELECT(run_id,source_id,status,accepted_documents,suppressed_documents),
      UPDATE(status,error_code,finished_at,accepted_documents,suppressed_documents,
             raw_sha256,http_status)
 ON ow.collection_runs TO ow_collector;
GRANT SELECT(source_id,resource_sha256,next_attempt,failures,etag,last_modified,raw_sha256),
      INSERT(source_id,resource_sha256),
      UPDATE(resource_sha256,next_attempt,failures,etag,last_modified,raw_sha256)
 ON ow.collection_state TO ow_collector;
