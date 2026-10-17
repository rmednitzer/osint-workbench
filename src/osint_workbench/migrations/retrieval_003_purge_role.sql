-- Add only explicit optional-profile purge authority; published profiles remain immutable.
GRANT SELECT ON ow.retrieval_migrations,ow.embedding_spaces,ow.retrieval_generations,
  ow.retrieval_members,ow.retrieval_vectors,ow.retrieval_active TO ow_purger;
GRANT DELETE ON ow.retrieval_vectors,ow.retrieval_members,ow.retrieval_active TO ow_purger;
GRANT UPDATE(status,error_code) ON ow.retrieval_generations TO ow_purger;
