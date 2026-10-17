-- Explicit private operator authority; no source/reader/worker identity inherits it.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ow_purger') THEN
    CREATE ROLE ow_purger NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
ALTER TABLE ow.lifecycle_events DROP CONSTRAINT lifecycle_events_action_check;
ALTER TABLE ow.lifecycle_events ADD CONSTRAINT lifecycle_events_action_check
  CHECK(action IN ('retention','hold','release','retire','purge'));
GRANT USAGE ON SCHEMA ow TO ow_purger;
GRANT SELECT ON
  ow.migrations,ow.sources,ow.snapshots,ow.documents,ow.document_heads,
  ow.jobs,ow.job_events,ow.chunks,ow.collection_runs,ow.collection_state,
  ow.enrichments,ow.assertions,ow.assertion_reviews,ow.briefings,
  ow.lifecycle_control,ow.lifecycle_items,ow.lifecycle_holds,
  ow.lifecycle_tombstones,ow.lifecycle_events
 TO ow_purger;
GRANT DELETE ON
  ow.snapshots,ow.documents,ow.document_heads,ow.jobs,ow.job_events,ow.chunks,
  ow.enrichments,ow.assertions,ow.assertion_reviews,ow.briefings
 TO ow_purger;
GRANT UPDATE(revision) ON ow.lifecycle_control TO ow_purger;
GRANT INSERT ON ow.lifecycle_events TO ow_purger;
