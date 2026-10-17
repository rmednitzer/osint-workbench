-- Optional profile. Requires operator provisioning and core migration v2.
CREATE SCHEMA ow_vector;
CREATE EXTENSION vector WITH SCHEMA ow_vector;
GRANT USAGE ON SCHEMA ow_vector TO ow_reader,ow_writer;
CREATE TABLE ow.retrieval_migrations(version integer PRIMARY KEY,sha256 text NOT NULL);
CREATE TABLE ow.embedding_spaces (
  space_id text PRIMARY KEY CHECK (space_id ~ '^[0-9a-f]{64}$'),
  manifest jsonb NOT NULL,
  dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 16000),
  UNIQUE(space_id,dimensions)
);
CREATE TABLE ow.retrieval_generations (
  generation_id uuid PRIMARY KEY,
  space_id text NOT NULL,
  dimensions integer NOT NULL,
  corpus_sha256 text NOT NULL,
  status text NOT NULL CHECK (status IN ('building','ready','failed')),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(generation_id,space_id,dimensions),
  FOREIGN KEY(space_id,dimensions) REFERENCES ow.embedding_spaces(space_id,dimensions)
);
CREATE TABLE ow.retrieval_members (
  generation_id uuid NOT NULL REFERENCES ow.retrieval_generations,
  document_id text NOT NULL REFERENCES ow.documents,
  PRIMARY KEY(generation_id,document_id)
);
CREATE TABLE ow.retrieval_vectors (
  generation_id uuid NOT NULL,
  space_id text NOT NULL,
  dimensions integer NOT NULL,
  document_id text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  start_offset integer NOT NULL CHECK (start_offset >= 0),
  end_offset integer NOT NULL CHECK (end_offset > start_offset),
  text_sha256 text NOT NULL,
  embedding ow_vector.vector NOT NULL,
  CHECK (ow_vector.vector_dims(embedding)=dimensions),
  FOREIGN KEY(generation_id,space_id,dimensions)
    REFERENCES ow.retrieval_generations(generation_id,space_id,dimensions),
  FOREIGN KEY(generation_id,document_id) REFERENCES ow.retrieval_members,
  PRIMARY KEY(generation_id,document_id,ordinal)
);
CREATE INDEX retrieval_vectors_generation ON ow.retrieval_vectors(generation_id);
CREATE TABLE ow.retrieval_active (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  generation_id uuid NOT NULL REFERENCES ow.retrieval_generations
);
GRANT SELECT ON ow.embedding_spaces,ow.retrieval_generations,ow.retrieval_members,
  ow.retrieval_vectors,ow.retrieval_active TO ow_reader;
GRANT SELECT,INSERT ON ow.embedding_spaces,ow.retrieval_members,ow.retrieval_vectors TO ow_writer;
GRANT SELECT,INSERT,UPDATE ON ow.retrieval_generations,ow.retrieval_active TO ow_writer;
GRANT SELECT ON ow.active_documents TO ow_writer;
