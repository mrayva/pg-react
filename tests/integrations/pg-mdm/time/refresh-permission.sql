\set ON_ERROR_STOP on
BEGIN;
CREATE ROLE compatibility_owner LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE compatibility_worker LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA compatibility_private AUTHORIZATION compatibility_owner;
CREATE SCHEMA compatibility_stream AUTHORIZATION compatibility_owner;
GRANT USAGE ON SCHEMA pgtrickle TO compatibility_owner, compatibility_worker;
GRANT USAGE ON SCHEMA compatibility_stream TO compatibility_worker;
-- Public-call grants let these probes reach object authorization, as React's role setup does.
DO $callables$
DECLARE callable record;
BEGIN
    FOR callable IN SELECT p.oid::regprocedure AS signature, p.proname
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='pgtrickle' AND p.proname IN
            ('create_stream_table','refresh_stream_table','alter_stream_table','drop_stream_table') LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',callable.signature,
            CASE WHEN callable.proname='create_stream_table' THEN 'compatibility_owner'
                 ELSE 'compatibility_worker' END);
    END LOOP;
END
$callables$;
SET SESSION AUTHORIZATION compatibility_owner;
CREATE TABLE compatibility_private.source(id bigint PRIMARY KEY, value text NOT NULL);
INSERT INTO compatibility_private.source VALUES (1,'first');
SELECT pgtrickle.create_stream_table('compatibility_stream.target',
    'SELECT id,value FROM compatibility_private.source', '1h', 'DIFFERENTIAL', true);
SELECT pgtrickle.create_stream_table('compatibility_stream.unrelated',
    'SELECT id,value FROM compatibility_private.source', '1h', 'DIFFERENTIAL', true);
INSERT INTO compatibility_private.source VALUES (2,'second');
RESET SESSION AUTHORIZATION;

CREATE FUNCTION pg_temp.expect_denied(statement text, message text)
RETURNS void LANGUAGE plpgsql AS $test$
BEGIN
    BEGIN
        EXECUTE statement;
        RAISE EXCEPTION 'unauthorized operation succeeded: %', statement;
    EXCEPTION WHEN insufficient_privilege THEN
        IF SQLERRM <> message THEN RAISE; END IF;
    END;
END
$test$;
GRANT MAINTAIN ON compatibility_stream.unrelated TO compatibility_worker;
SET SESSION AUTHORIZATION compatibility_worker;
SELECT pg_temp.expect_denied(
    'SELECT pgtrickle.refresh_stream_table(''compatibility_stream.target'')',
    'permission denied: must own stream table compatibility_stream.target or have MAINTAIN on that exact relation');
RESET SESSION AUTHORIZATION;
GRANT MAINTAIN ON compatibility_stream.target TO compatibility_worker;

DO $privileges$
DECLARE actual jsonb;
BEGIN
    SELECT jsonb_build_object('owner',pg_get_userbyid(c.relowner),
        'stream_privileges',(SELECT jsonb_agg(privilege ORDER BY privilege)
            FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) privilege
            WHERE has_table_privilege('compatibility_worker',c.oid,privilege)),
        'source_select',has_table_privilege('compatibility_worker','compatibility_private.source','SELECT'),
        'source_usage',has_schema_privilege('compatibility_worker','compatibility_private','USAGE'),
        'owner_membership',pg_has_role('compatibility_worker','compatibility_owner','MEMBER'),
        'superuser',r.rolsuper,'bypassrls',r.rolbypassrls)
    INTO actual FROM pg_class c, pg_roles r
    WHERE c.oid = 'compatibility_stream.target'::regclass AND r.rolname = 'compatibility_worker';
    IF actual IS DISTINCT FROM '{"owner":"compatibility_owner","stream_privileges":["MAINTAIN"],
        "source_select":false,"source_usage":false,"owner_membership":false,
        "superuser":false,"bypassrls":false}'::jsonb THEN
        RAISE EXCEPTION 'refresh privilege vector differs: %', actual;
    END IF;
    RAISE NOTICE 'refresh privilege vector: %', actual;
END
$privileges$;
SET SESSION AUTHORIZATION compatibility_worker;
SELECT pgtrickle.refresh_stream_table('compatibility_stream.target');
SELECT pg_temp.expect_denied(
    'SELECT pgtrickle.alter_stream_table(''compatibility_stream.target'',schedule=>''2h'')',
    'permission denied: must be owner of stream table compatibility_stream.target');
SELECT pg_temp.expect_denied(
    'SELECT pgtrickle.drop_stream_table(''compatibility_stream.target'')',
    'permission denied: must be owner of stream table compatibility_stream.target');
RESET SESSION AUTHORIZATION;
REVOKE MAINTAIN ON compatibility_stream.target FROM compatibility_worker;
SET SESSION AUTHORIZATION compatibility_worker;
SELECT pg_temp.expect_denied(
    'SELECT pgtrickle.refresh_stream_table(''compatibility_stream.target'')',
    'permission denied: must own stream table compatibility_stream.target or have MAINTAIN on that exact relation');
RESET SESSION AUTHORIZATION;
DO $state$
DECLARE actual jsonb;
BEGIN
    SELECT jsonb_agg(jsonb_build_object('id',id,'value',value) ORDER BY id) INTO actual
    FROM compatibility_stream.target;
    IF actual IS DISTINCT FROM '[{"id":1,"value":"first"},{"id":2,"value":"second"}]'::jsonb
       OR actual IS DISTINCT FROM (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM compatibility_private.source s)
       OR (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='compatibility_stream.target'::regclass)
          IS DISTINCT FROM 'compatibility_owner' THEN
        RAISE EXCEPTION 'refresh/denial changed source, owner or exact output: %',actual;
    END IF;
END
$state$;
ROLLBACK;
SELECT 'exact-target MAINTAIN without source access; revoked/unrelated grants and lifecycle denied: PASS';
