-- Optional retrieval-profile migration 2, not core migration 5.
CREATE VIEW ow.visible_retrieval_members WITH (security_barrier=true) AS
 SELECT m.* FROM ow.retrieval_members m JOIN ow.visible_documents d USING(document_id);
CREATE VIEW ow.visible_retrieval_vectors WITH (security_barrier=true) AS
 SELECT v.* FROM ow.retrieval_vectors v JOIN ow.visible_documents d USING(document_id);
REVOKE SELECT ON ow.retrieval_members,ow.retrieval_vectors FROM ow_reader;
GRANT SELECT ON ow.visible_retrieval_members,ow.visible_retrieval_vectors TO ow_reader,ow_writer;
