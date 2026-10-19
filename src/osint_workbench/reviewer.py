"""Check the actual review connection before accepting attributed decisions."""

from .errors import WorkbenchError


def validate_connection(conn):
    """Refuse overlapping, privileged, delegated or broadened runtime authority.

    Checks include PUBLIC and inherited ACLs. Database owners must provision a
    dedicated login; an actor string never substitutes for that credential.
    Concurrent administrator changes and malicious database owners are outside
    this boundary. The SQL trigger separately denies direct writer reviews.
    """
    unsafe = conn.execute("""SELECT
      session_user<>current_user AS changed_identity,
      NOT pg_has_role(current_user,'ow_reviewer','USAGE') AS no_reviewer,
      EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'MEMBER')
        AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls
          OR r.rolreplication OR r.rolname NOT IN (current_user,'ow_reviewer')))
        AS unsafe_roles,
      EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ow_reviewer' AND rolcanlogin)
        AS login_group,
      EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.admin_option
        AND pg_has_role(current_user,m.member,'MEMBER')) AS role_delegation,
      EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database()
        AND (pg_has_role(current_user,datdba,'MEMBER')
          OR has_database_privilege(current_user,oid,'CREATE'))) AS database_authority,
      EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('ow','ow_vector','public')
        AND (pg_has_role(current_user,n.nspowner,'MEMBER')
          OR has_schema_privilege(current_user,n.oid,'CREATE')
          OR has_schema_privilege(current_user,n.oid,'USAGE WITH GRANT OPTION')))
        AS schema_authority,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND
        (pg_has_role(current_user,c.relowner,'MEMBER')
          OR (c.relkind IN ('r','p','v','m','f') AND has_table_privilege(current_user,c.oid,
            'DELETE,TRUNCATE,TRIGGER,REFERENCES,MAINTAIN')))) AS relation_authority,
      EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname IN ('ow','ow_vector') AND
        (pg_has_role(current_user,p.proowner,'MEMBER') OR
          (p.prosecdef AND has_schema_privilege(current_user,n.oid,'USAGE')
           AND has_function_privilege(current_user,p.oid,'EXECUTE')))) AS function_authority,
      EXISTS(SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
        WHERE n.nspname IN ('ow','ow_vector')
          AND pg_has_role(current_user,t.typowner,'MEMBER')) AS type_authority,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND c.relkind='S' AND
          (has_sequence_privilege(current_user,c.oid,'SELECT,UPDATE') OR
           has_sequence_privilege(current_user,c.oid,'USAGE WITH GRANT OPTION') OR
           ((n.nspname,c.relname)<>('ow','assertion_reviews_review_id_seq') AND
             has_sequence_privilege(current_user,c.oid,'USAGE')))) AS sequence_authority
    """).fetchone()
    if any(unsafe.values()):
        raise WorkbenchError("UNSAFE_REVIEWER_IDENTITY")
    allowed = {
        ("current_assertions", column, "SELECT")
        for column in (
            "assertion_id enrichment_id document_id subject predicate object statement "
            "polarity start_offset end_offset quote review_state"
        ).split()
    } | {
        ("assertion_reviews", column, "INSERT")
        for column in "assertion_id decision actor rationale".split()
    }
    rows = conn.execute("""SELECT c.relname,a.attname,p.privilege,
        has_column_privilege(current_user,c.oid,a.attnum,
          p.privilege || ' WITH GRANT OPTION') AS delegated
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
      CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
      WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
        AND has_column_privilege(current_user,c.oid,a.attnum,p.privilege)""").fetchall()
    if (
        {(r["relname"], r["attname"], r["privilege"]) for r in rows} != allowed
        or any(r["delegated"] for r in rows)
        or conn.execute("""SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='ow' AND c.relname IN ('assertions','assertion_reviews')
            AND (c.relrowsecurity OR c.relforcerowsecurity) LIMIT 1""").fetchone()
    ):
        raise WorkbenchError("UNSAFE_REVIEWER_IDENTITY")
