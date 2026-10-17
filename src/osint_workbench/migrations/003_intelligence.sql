CREATE TABLE ow.enrichments (
  enrichment_id text PRIMARY KEY,
  document_id text NOT NULL REFERENCES ow.documents,
  job_id uuid NOT NULL UNIQUE REFERENCES ow.jobs,
  generator_id text NOT NULL,
  prompt_version text NOT NULL,
  prompt_sha256 text NOT NULL,
  response_sha256 text NOT NULL,
  status text NOT NULL CHECK (status IN ('proposed','abstained')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE ow.assertions (
  assertion_id text PRIMARY KEY,
  enrichment_id text NOT NULL REFERENCES ow.enrichments,
  document_id text NOT NULL REFERENCES ow.documents,
  subject text NOT NULL,
  predicate text NOT NULL CHECK (predicate IN ('mentions','affects','mitigates','deadline','related_to')),
  object text NOT NULL,
  statement text NOT NULL,
  polarity text NOT NULL CHECK (polarity IN ('asserted','negated','uncertain')),
  start_offset integer NOT NULL CHECK (start_offset >= 0),
  end_offset integer NOT NULL CHECK (end_offset > start_offset),
  quote text NOT NULL,
  CHECK (length(quote)=end_offset-start_offset)
);
CREATE INDEX assertions_document ON ow.assertions(document_id);
CREATE TABLE ow.assertion_reviews (
  review_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  assertion_id text NOT NULL REFERENCES ow.assertions,
  decision text NOT NULL CHECK (decision IN ('accept','reject')),
  actor text NOT NULL,
  rationale text NOT NULL,
  reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE VIEW ow.current_assertions AS
 SELECT a.*,coalesce(r.decision,'pending') AS review_state
 FROM ow.assertions a JOIN ow.active_documents d USING(document_id)
 LEFT JOIN LATERAL (
   SELECT decision FROM ow.assertion_reviews r WHERE r.assertion_id=a.assertion_id
   ORDER BY review_id DESC LIMIT 1
 ) r ON true;
CREATE TABLE ow.briefings (
  briefing_id text PRIMARY KEY,
  content jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
GRANT SELECT,INSERT ON ow.enrichments,ow.assertions,ow.assertion_reviews,ow.briefings TO ow_writer;
GRANT SELECT ON ow.current_assertions TO ow_reader,ow_writer;
GRANT SELECT ON ow.assertions,ow.briefings TO ow_reader;
GRANT USAGE ON SEQUENCE ow.assertion_reviews_review_id_seq TO ow_writer;
GRANT SELECT ON ow.active_documents TO ow_writer;
