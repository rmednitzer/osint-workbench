-- Private scheduling and HTTP validators; no operational URLs are stored.
CREATE TABLE ow.collection_state (
  source_id text PRIMARY KEY REFERENCES ow.sources,
  resource_sha256 text NOT NULL CHECK(resource_sha256 ~ '^[0-9a-f]{64}$'),
  next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),
  failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 32),
  etag text CHECK(octet_length(etag)<=512 AND etag !~ '[[:cntrl:]]'),
  last_modified text CHECK(octet_length(last_modified)<=128 AND last_modified !~ '[[:cntrl:]]'),
  raw_sha256 text CHECK(raw_sha256 ~ '^[0-9a-f]{64}$'),
  CHECK((etag IS NULL AND last_modified IS NULL) OR raw_sha256 IS NOT NULL)
);
GRANT SELECT,INSERT,UPDATE ON ow.collection_state TO ow_writer;

ALTER TABLE ow.collection_runs ADD COLUMN http_status integer CHECK(http_status IN (200,304));
