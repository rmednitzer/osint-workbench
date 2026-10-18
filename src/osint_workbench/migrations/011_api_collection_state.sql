-- Additive core migration 11: private resumable API progress, not credentials.
-- Reader roles deliberately receive no access to this acquisition-only state.
ALTER TABLE ow.collection_state
  ADD COLUMN api_cursor text
    CHECK (octet_length(api_cursor) <= 1024 AND api_cursor !~ '[[:cntrl:]]'),
  ADD COLUMN api_profile_sha256 text CHECK (api_profile_sha256 ~ '^[0-9a-f]{64}$'),
  ADD COLUMN api_page integer NOT NULL DEFAULT 0 CHECK (api_page BETWEEN 0 AND 128),
  ADD COLUMN api_seen_cursors jsonb NOT NULL DEFAULT '[]'::jsonb
    CHECK (CASE WHEN jsonb_typeof(api_seen_cursors) = 'array'
      THEN jsonb_array_length(api_seen_cursors) <= 128
        AND octet_length(api_seen_cursors::text) <= 10000
      ELSE false END);
GRANT SELECT(api_cursor,api_profile_sha256,api_page,api_seen_cursors),
      UPDATE(api_cursor,api_profile_sha256,api_page,api_seen_cursors)
 ON ow.collection_state TO ow_collector;
