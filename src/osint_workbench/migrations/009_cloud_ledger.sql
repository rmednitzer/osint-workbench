-- Additive core migration 9: remote dispatch decisions and conservative exposure.
-- Rows hold digests and accounting, never prompts, responses or credentials.
CREATE TABLE ow.remote_operations (
  attempt_id uuid PRIMARY KEY,
  operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 200),
  route_id text NOT NULL CHECK (route_id ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
  policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  task text NOT NULL,
  data_class text,
  decision text NOT NULL CHECK (decision IN ('denied','conforming','exception')),
  reason text,
  packet_sha256 text NOT NULL CHECK (packet_sha256 ~ '^[0-9a-f]{64}$'),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  reserved numeric(20,9) NOT NULL CHECK (reserved >= 0),
  status text NOT NULL CHECK (status IN ('denied','reserved','dispatched','completed',
    'refused','incomplete','failed','outcome_unknown','released')),
  input_tokens integer CHECK (input_tokens >= 0),
  output_tokens integer CHECK (output_tokens >= 0),
  usage text CHECK (usage IN ('reported','missing')),
  estimated_cost numeric(20,9) CHECK (estimated_cost >= 0),
  response_sha256 text CHECK (response_sha256 ~ '^[0-9a-f]{64}$'),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((decision = 'denied') = (status = 'denied')),
  CHECK (usage IS DISTINCT FROM 'reported' OR estimated_cost IS NOT NULL)
);
CREATE INDEX remote_operations_exposure ON ow.remote_operations(route_id,currency);
CREATE INDEX remote_operations_operation ON ow.remote_operations(operation_id);
GRANT SELECT,INSERT ON ow.remote_operations TO ow_writer;
GRANT UPDATE(status,input_tokens,output_tokens,usage,estimated_cost,response_sha256,
  error_code,updated_at) ON ow.remote_operations TO ow_writer;
GRANT SELECT ON ow.remote_operations TO ow_purger;
