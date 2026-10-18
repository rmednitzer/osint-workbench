-- Additive authority for item-version reuse; published migrations remain unchanged.
-- The collector may resolve a current head to its container digest. It still
-- cannot read titles, bodies, text digests or another worker's derived records.
GRANT SELECT(snapshot_id) ON ow.documents TO ow_collector;
GRANT SELECT(snapshot_id,raw_sha256) ON ow.snapshots TO ow_collector;
