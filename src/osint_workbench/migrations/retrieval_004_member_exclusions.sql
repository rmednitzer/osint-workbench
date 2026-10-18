-- Optional retrieval-profile migration 4; published profile migrations remain unchanged.
-- A member is either encoded (has vectors) or carries one explicit content refusal.
CREATE TABLE ow.retrieval_exclusions (
  generation_id uuid NOT NULL,
  document_id text NOT NULL,
  reason text NOT NULL CHECK (reason IN ('INVALID_ENCODER_INPUT','ENCODER_PACKET_TOO_LARGE',
    'ENCODER_INPUT_TOO_LONG','TOKEN_OFFSETS_UNSUPPORTED','ENCODER_CHUNK_LIMIT',
    'ENCODER_RESULT_LIMIT','INVALID_EMBEDDING_NORM')),
  PRIMARY KEY(generation_id,document_id),
  FOREIGN KEY(generation_id,document_id) REFERENCES ow.retrieval_members
);
CREATE VIEW ow.visible_retrieval_exclusions WITH (security_barrier=true) AS
 SELECT e.* FROM ow.retrieval_exclusions e JOIN ow.visible_documents d USING(document_id);
GRANT SELECT,INSERT ON ow.retrieval_exclusions TO ow_writer;
GRANT SELECT ON ow.visible_retrieval_exclusions TO ow_reader,ow_writer;
GRANT SELECT,DELETE ON ow.retrieval_exclusions TO ow_purger;
