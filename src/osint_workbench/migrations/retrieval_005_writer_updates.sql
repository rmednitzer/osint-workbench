-- Identity, corpus, dimensions and timestamps are not mutable writer fields.
REVOKE UPDATE ON ow.retrieval_generations,ow.retrieval_active FROM ow_writer;
GRANT UPDATE(status,error_code) ON ow.retrieval_generations TO ow_writer;
GRANT UPDATE(generation_id) ON ow.retrieval_active TO ow_writer;
