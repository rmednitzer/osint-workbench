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
  reserved numeric(15,9) NOT NULL CHECK (reserved >= 0),
  status text NOT NULL CHECK (status IN ('denied','reserved','dispatched','completed',
    'refused','incomplete','failed','outcome_unknown','released')),
  input_tokens integer CHECK (input_tokens >= 0),
  output_tokens integer CHECK (output_tokens >= 0),
  usage text CHECK (usage IN ('reported','missing')),
  estimated_cost numeric(15,9) CHECK (estimated_cost >= 0),
  response_sha256 text CHECK (response_sha256 ~ '^[0-9a-f]{64}$'),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((decision = 'denied') = (status = 'denied')),
  CHECK (usage IS DISTINCT FROM 'reported' OR estimated_cost IS NOT NULL),
  CHECK (estimated_cost IS NULL OR estimated_cost <= reserved)
);
-- Outcome writes follow the attempt state machine once; a writer cannot move a
-- terminal attempt, skip dispatch or rewrite the decision and reservation.
CREATE FUNCTION ow.remote_operation_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NOT ((OLD.status = 'reserved' AND NEW.status = 'dispatched')
      OR (OLD.status = 'dispatched' AND NEW.status IN
          ('released','completed','refused','incomplete','failed','outcome_unknown')))
     OR (OLD.status = 'reserved' AND (NEW.usage IS NOT NULL OR NEW.estimated_cost IS NOT NULL
         OR NEW.response_sha256 IS NOT NULL))
     OR (NEW.status = 'released' AND (NEW.usage IS NOT NULL OR NEW.response_sha256 IS NOT NULL))
  THEN
    RAISE EXCEPTION 'invalid remote operation transition' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ow.remote_operation_transition() FROM PUBLIC;
CREATE TRIGGER remote_operation_transition BEFORE UPDATE ON ow.remote_operations
  FOR EACH ROW EXECUTE FUNCTION ow.remote_operation_transition();
CREATE INDEX remote_operations_exposure ON ow.remote_operations(route_id,currency);
CREATE INDEX remote_operations_operation ON ow.remote_operations(operation_id);
GRANT SELECT,INSERT ON ow.remote_operations TO ow_writer;
GRANT UPDATE(status,input_tokens,output_tokens,usage,estimated_cost,response_sha256,
  error_code,updated_at) ON ow.remote_operations TO ow_writer;
GRANT SELECT ON ow.remote_operations TO ow_purger;
