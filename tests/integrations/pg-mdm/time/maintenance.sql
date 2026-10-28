\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
CREATE SCHEMA claim_maintenance;
\if :direct
-- Run with -v upgrade=true for the populated 0.46.0 -> 0.46.1 lane.
DO $roles$
DECLARE role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'claim_maintenance_author', 'claim_maintenance_login',
        'claim_maintenance_unrelated', 'claim_maintenance_rotated_worker',
        'claim_maintenance_operator', 'claim_maintenance_worker',
        'claim_maintenance_reader', 'claim_maintenance_advanced_reader']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS', role_name);
        END IF;
    END LOOP;
END
$roles$;
GRANT claim_maintenance_worker TO claim_maintenance_login WITH INHERIT TRUE;
GRANT USAGE ON SCHEMA pgreact_api TO claim_maintenance_unrelated, claim_maintenance_rotated_worker;
SELECT pgreact_api.configure_roles('claim_maintenance_author', 'claim_maintenance_operator',
    'claim_maintenance_worker', 'claim_maintenance_reader', 'claim_maintenance_advanced_reader');
\endif

\if :upgrade
DO $red$
BEGIN
    PERFORM * FROM pgreact.claim('maintenance-red', 1);
    RAISE EXCEPTION 'predecessor unexpectedly lacks the reproduced ambiguity';
EXCEPTION WHEN ambiguous_column THEN
    IF SQLERRM <> 'column reference "rule_version_id" is ambiguous' THEN RAISE; END IF;
END
$red$;
\else
DO $empty$
BEGIN
    IF (SELECT COALESCE(jsonb_agg(to_jsonb(c)), '[]') FROM pgreact.claim('empty', 1) c)
        <> '[]'::jsonb THEN RAISE EXCEPTION 'empty claim returned work'; END IF;
END
$empty$;
\endif

\if :direct
CREATE TABLE claim_maintenance.source(id bigint PRIMARY KEY, deadline timestamptz NOT NULL);
CREATE TABLE claim_maintenance.actions(id bigint PRIMARY KEY, deadline timestamptz NOT NULL);
INSERT INTO claim_maintenance.source VALUES
    (1, '2000-01-01 00:00:00+00'), (2, '2000-01-02 00:00:00+00'),
    (3, '2100-01-01 00:00:00+00');
CREATE VIEW claim_maintenance.candidate AS SELECT id, deadline FROM claim_maintenance.source;
CREATE FUNCTION claim_maintenance.deliver(
    context pgreact.activation_context, candidate claim_maintenance.candidate
) RETURNS void LANGUAGE SQL AS $callback$
    INSERT INTO claim_maintenance.actions VALUES (($2).id, ($2).deadline)
$callback$;
SELECT pgreact_api.author_deadline_rule('maintenance-claim',
    'claim_maintenance.candidate'::regclass, 'id', 'deadline', 'COMMAND',
    'claim_maintenance.deliver(pgreact.activation_context,claim_maintenance.candidate)');
SELECT pgreact_api.run(clock_timestamp());

CREATE TEMP TABLE held AS
SELECT * FROM pgreact.claim_episode(
    (SELECT rule_version_id FROM pgreact.rules WHERE rule_name='maintenance-claim'),
    'maintenance-held', 60);
\endif

-- Capture every core/adapter-owned table and public MDM state; no private MDM reads.
CREATE FUNCTION claim_maintenance.state() RETURNS jsonb LANGUAGE plpgsql AS $state$
DECLARE result jsonb := '{}'::jsonb; relation record; rows jsonb;
BEGIN
    FOR relation IN
        SELECT n.nspname, c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('pgreact_internal','pgreact_mdm') AND c.relkind='r'
        ORDER BY n.nspname,c.relname
    LOOP
        EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),''[]'') FROM %I.%I t',
            relation.nspname,relation.relname) INTO rows;
        result := result || jsonb_build_object(relation.nspname || '.' || relation.relname,rows);
    END LOOP;
    IF to_regclass('mdm_steward.policy_cases_v1') IS NOT NULL THEN
        result := result || jsonb_build_object(
            'mdm_cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c),
            'mdm_receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM mdm_steward.policy_receipts_v1 r));
    END IF;
    RETURN result;
END
$state$;
CREATE FUNCTION claim_maintenance.api() RETURNS jsonb LANGUAGE SQL AS $api$
SELECT jsonb_agg(jsonb_build_object(
    'identity',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),
    'result',pg_get_function_result(p.oid),'acl',p.proacl::text,
    'security_definer',p.prosecdef,'config',p.proconfig,
    'volatility',p.provolatile,'parallel',p.proparallel,
    'definition',pg_get_functiondef(p.oid)) ORDER BY p.oid::regprocedure::text)
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname IN ('pgreact','pgreact_api') AND p.prokind='f'
$api$;
CREATE TABLE claim_maintenance.before_upgrade AS
SELECT claim_maintenance.state() AS state, claim_maintenance.api() AS api;
\if :upgrade
ALTER EXTENSION pg_react UPDATE TO '0.46.1';
DO $preserved$
DECLARE expected_api jsonb; worker_acl aclitem; extension_owner oid;
BEGIN
    SELECT extowner INTO STRICT extension_owner FROM pg_extension WHERE extname='pg_react';
    SELECT format('%s=X/%s', role_oid::regrole::text, extension_owner::regrole::text)::aclitem
    INTO worker_acl FROM pgreact_internal.application_roles WHERE role_kind='worker';
    SELECT jsonb_agg(CASE WHEN item->>'identity'='pgreact.claim(text,integer,interval,text[])'
        THEN jsonb_set(item,'{definition}',to_jsonb(replace(item->>'definition',
            E'        SELECT rule_version_id\n        FROM pgreact_internal.rule_versions\n        WHERE state IN (''ACTIVE'', ''DRAINING'')\n        ORDER BY rule_version_id',
            E'        SELECT version.rule_version_id\n        FROM pgreact_internal.rule_versions AS version\n        WHERE version.state IN (''ACTIVE'', ''DRAINING'')\n        ORDER BY version.rule_version_id')))
        WHEN item->>'identity'='pgreact_api.managed_cycle()'
             AND worker_acl IS NOT NULL
             AND NOT worker_acl=ANY(COALESCE((item->>'acl')::aclitem[],acldefault('f',extension_owner)))
        THEN jsonb_set(item,'{acl}',to_jsonb((COALESCE((item->>'acl')::aclitem[],
            acldefault('f',extension_owner)) || worker_acl)::text))
        ELSE item END ORDER BY item->>'identity')
    INTO expected_api FROM claim_maintenance.before_upgrade, jsonb_array_elements(api) item;
    IF claim_maintenance.state() IS DISTINCT FROM (SELECT state FROM claim_maintenance.before_upgrade)
       OR claim_maintenance.api() IS DISTINCT FROM expected_api THEN
        RAISE EXCEPTION 'populated upgrade changed state or unrelated callable/role inventory';
    END IF;
END
$preserved$;
\endif

CREATE TABLE claim_maintenance.after_upgrade AS
SELECT claim_maintenance.state() AS state, claim_maintenance.api() AS api;

\if :direct
SET SESSION AUTHORIZATION claim_maintenance_login;
CREATE TEMP TABLE claimed AS SELECT * FROM pgreact_api.claim('maintenance-worker',1,interval '1 second');
RESET SESSION AUTHORIZATION;
DO $claimed$
DECLARE actual jsonb; expected jsonb;
BEGIN
    SELECT jsonb_agg(to_jsonb(c)) INTO actual FROM claimed c;
    SELECT jsonb_agg(jsonb_build_object(
        'episode_id',a.episode_id,'lease_token',a.lease_token,'activation_id',a.activation_id,
        'bindings',a.new_bindings,'event_kind','ACTIVATE','rule_version_id',a.rule_version_id))
    INTO expected FROM pgreact_internal.agenda a
    WHERE a.worker_id='maintenance-worker' AND a.state='LEASED';
    IF actual IS DISTINCT FROM expected
       OR (SELECT bindings FROM claimed) IS DISTINCT FROM
          jsonb_build_object('id',2,'deadline','2000-01-02T00:00:00+00:00','__pgt_row_id',decode('02010000000104018000000000000002ff','hex')::text)
       OR (SELECT bindings FROM held) IS DISTINCT FROM
          jsonb_build_object('id',1,'deadline','2000-01-01T00:00:00+00:00','__pgt_row_id',decode('02010000000104018000000000000001ff','hex')::text)
       OR (SELECT COALESCE(jsonb_agg(to_jsonb(c)),'[]') FROM pgreact.claim('other-worker',1) c)
          IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'complete claim result or leased-work exclusion mismatch: %, %', actual,expected;
    END IF;
END
$claimed$;
DO $invalid$
DECLARE arguments record; actual text;
BEGIN
    FOR arguments IN SELECT * FROM (VALUES
        (0,interval '1 second','max_items must be between 1 and 100'),
        (101,interval '1 second','max_items must be between 1 and 100'),
        (1,interval '0 seconds','lease_for must be at least one second')) v(items,lease,message)
    LOOP
        actual := NULL;
        BEGIN PERFORM * FROM pgreact_api.claim('invalid',arguments.items,arguments.lease);
        EXCEPTION WHEN OTHERS THEN actual := SQLERRM; END;
        IF actual IS DISTINCT FROM arguments.message THEN
            RAISE EXCEPTION 'invalid claim error mismatch: %', actual;
        END IF;
    END LOOP;
END
$invalid$;
DO $expired$
DECLARE stop_at timestamptz := clock_timestamp()+interval '5 seconds';
BEGIN
    WHILE EXISTS (SELECT 1 FROM pgreact_internal.agenda a
        JOIN claimed c USING (episode_id) WHERE a.lease_expires_at > clock_timestamp())
    LOOP
        IF clock_timestamp()>stop_at THEN RAISE EXCEPTION 'lease expiry exceeded deadline'; END IF;
        PERFORM pg_sleep(0.05);
    END LOOP;
END
$expired$;
CREATE TEMP TABLE reclaimed AS SELECT * FROM pgreact.claim('maintenance-retry',1,interval '60 seconds');
DO $retry$
DECLARE old_claim record; new_claim record; status text;
BEGIN
    SELECT * INTO STRICT old_claim FROM claimed;
    SELECT * INTO STRICT new_claim FROM reclaimed;
    IF (to_jsonb(new_claim)-'lease_token') IS DISTINCT FROM (to_jsonb(old_claim)-'lease_token')
       OR new_claim.lease_token=old_claim.lease_token THEN
        RAISE EXCEPTION 'retry changed immutable result or reused stale lease token';
    END IF;
    BEGIN
        PERFORM pgreact_api.execute(old_claim.episode_id,'maintenance-worker',old_claim.lease_token);
        RAISE EXCEPTION 'stale lease was accepted';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE 'lease is no longer valid%' THEN RAISE; END IF;
    END;
    status := pgreact_api.execute(new_claim.episode_id,'maintenance-retry',new_claim.lease_token);
    IF status <> 'COMPLETED' THEN RAISE EXCEPTION 'retry execution: %',status; END IF;
    SELECT * INTO STRICT old_claim FROM held;
    status := pgreact_api.execute(old_claim.episode_id,'maintenance-held',old_claim.lease_token);
    IF status <> 'COMPLETED' THEN RAISE EXCEPTION 'preserved lease execution: %',status; END IF;
    IF (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM claim_maintenance.actions a)
        IS DISTINCT FROM '[{"id":1,"deadline":"2000-01-01T00:00:00+00:00"},{"id":2,"deadline":"2000-01-02T00:00:00+00:00"}]'::jsonb
       OR (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM claim_maintenance.source s)
        IS DISTINCT FROM '[{"id":1,"deadline":"2000-01-01T00:00:00+00:00"},{"id":2,"deadline":"2000-01-02T00:00:00+00:00"},{"id":3,"deadline":"2100-01-01T00:00:00+00:00"}]'::jsonb THEN
        RAISE EXCEPTION 'complete action/source population mismatch';
    END IF;
END
$retry$;
CREATE FUNCTION claim_maintenance.worker_privileges() RETURNS jsonb LANGUAGE SQL AS $privileges$
SELECT jsonb_object_agg(role_name,
    has_function_privilege(role_name,'pgreact_api.managed_cycle()','EXECUTE') ORDER BY role_name)
FROM unnest(ARRAY['claim_maintenance_author','claim_maintenance_operator',
    'claim_maintenance_worker','claim_maintenance_reader','claim_maintenance_advanced_reader',
    'claim_maintenance_login','claim_maintenance_unrelated',
    'claim_maintenance_rotated_worker']) AS roles(role_name)
$privileges$;
CREATE TABLE claim_maintenance.worker_role_results AS
SELECT claim_maintenance.worker_privileges() AS initial;
DO $admission$
BEGIN
    IF claim_maintenance.worker_privileges() IS DISTINCT FROM
       '{"claim_maintenance_author":false,"claim_maintenance_operator":false,
         "claim_maintenance_worker":true,"claim_maintenance_reader":false,
         "claim_maintenance_advanced_reader":false,"claim_maintenance_login":true,
         "claim_maintenance_unrelated":false,"claim_maintenance_rotated_worker":false}'::jsonb
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='claim_maintenance_login'
           AND rolcanlogin AND rolinherit AND NOT rolsuper AND NOT rolbypassrls) THEN
        RAISE EXCEPTION 'normal worker admission or denied role vector mismatch: %',
            claim_maintenance.worker_privileges();
    END IF;
END
$admission$;
-- Exercise actual public denials as each normal configured/non-worker caller.
SELECT format('SET SESSION AUTHORIZATION %I; DO $denied$ BEGIN
    PERFORM pgreact_api.managed_cycle();
    RAISE EXCEPTION ''non-worker entered managed_cycle'';
    EXCEPTION WHEN insufficient_privilege THEN
        IF SQLERRM <> ''permission denied for function managed_cycle'' THEN RAISE; END IF;
    END $denied$; RESET SESSION AUTHORIZATION;', role_name)
FROM unnest(ARRAY['claim_maintenance_author','claim_maintenance_operator',
    'claim_maintenance_reader','claim_maintenance_advanced_reader',
    'claim_maintenance_unrelated','claim_maintenance_rotated_worker']) AS roles(role_name)
\gexec
SELECT pgreact_api.configure_roles('claim_maintenance_author','claim_maintenance_operator',
    'claim_maintenance_rotated_worker','claim_maintenance_reader','claim_maintenance_advanced_reader');
ALTER TABLE claim_maintenance.worker_role_results ADD COLUMN rotated jsonb;
UPDATE claim_maintenance.worker_role_results SET rotated=claim_maintenance.worker_privileges();
DO $rotated$
BEGIN
    IF claim_maintenance.worker_privileges() IS DISTINCT FROM
       '{"claim_maintenance_author":false,"claim_maintenance_operator":false,
         "claim_maintenance_worker":false,"claim_maintenance_reader":false,
         "claim_maintenance_advanced_reader":false,"claim_maintenance_login":false,
         "claim_maintenance_unrelated":false,"claim_maintenance_rotated_worker":true}'::jsonb THEN
        RAISE EXCEPTION 'superseded worker retained managed authority: %',
            claim_maintenance.worker_privileges();
    END IF;
END
$rotated$;
SET SESSION AUTHORIZATION claim_maintenance_login;
DO $denied$
BEGIN
    PERFORM pgreact_api.managed_cycle();
    RAISE EXCEPTION 'superseded worker entered managed_cycle';
EXCEPTION WHEN insufficient_privilege THEN
    IF SQLERRM <> 'permission denied for function managed_cycle' THEN RAISE; END IF;
END
$denied$;
RESET SESSION AUTHORIZATION;
SELECT pgreact_api.configure_roles('claim_maintenance_author','claim_maintenance_operator',
    'claim_maintenance_worker','claim_maintenance_reader','claim_maintenance_advanced_reader');
ALTER TABLE claim_maintenance.worker_role_results ADD COLUMN restored jsonb;
UPDATE claim_maintenance.worker_role_results SET restored=claim_maintenance.worker_privileges();
DO $restored$
BEGIN
    IF claim_maintenance.worker_privileges() IS DISTINCT FROM
       (SELECT initial FROM claim_maintenance.worker_role_results) THEN
        RAISE EXCEPTION 'restored worker profile differs';
    END IF;
END
$restored$;
SELECT 'direct, lease/retry, role, error and populated-upgrade vectors: PASS';

CREATE TABLE claim_maintenance.result AS
SELECT jsonb_build_object(
    'worker_roles',(SELECT to_jsonb(r) FROM claim_maintenance.worker_role_results r),
    'held',(SELECT jsonb_agg(to_jsonb(c)) FROM held c),
    'claimed',(SELECT jsonb_agg(to_jsonb(c)) FROM claimed c),
    'reclaimed',(SELECT jsonb_agg(to_jsonb(c)) FROM reclaimed c),
    'actions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM claim_maintenance.actions a),
    'source',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM claim_maintenance.source s)) AS vector;

-- Separate from pg_react.batch_size (which bounds maintenance), the public
-- claim admission is a max_items argument subject to operational max_claims.
-- Prove two independent pending episodes cannot be leased in one max_items=1
-- invocation, and that the second remains available for a later claim.
INSERT INTO claim_maintenance.source VALUES
    (4, '2000-01-04 00:00:00+00'),
    (5, '2000-01-05 00:00:00+00');
SELECT pgreact_api.run(clock_timestamp());
DO $pending_claims$
DECLARE due_count bigint;
BEGIN
    SELECT count(*) INTO due_count
    FROM pgreact_internal.agenda AS agenda
    WHERE agenda.state IN ('PENDING', 'RETRY_WAIT')
      AND agenda.available_at <= clock_timestamp()
      AND agenda.rule_version_id = (
          SELECT rule_version_id FROM pgreact.rules
          WHERE rule_name = 'maintenance-claim');
    IF due_count <> 2 THEN
        RAISE EXCEPTION 'two fresh eligible episodes required, found %', due_count;
    END IF;
END
$pending_claims$;
CREATE TEMP TABLE first_bound_claim AS
SELECT * FROM pgreact.claim('bounded-1', 1, interval '60 seconds');
DO $first_bound$
DECLARE remaining bigint;
BEGIN
    SELECT count(*) INTO remaining
    FROM pgreact_internal.agenda AS agenda
    WHERE agenda.state = 'PENDING'
      AND agenda.available_at <= clock_timestamp()
      AND agenda.rule_version_id = (
          SELECT rule_version_id FROM pgreact.rules
          WHERE rule_name = 'maintenance-claim');
    IF (SELECT count(*) FROM first_bound_claim) <> 1 OR remaining <> 1
       OR (SELECT worker_id FROM pgreact_internal.agenda
           WHERE episode_id=(SELECT episode_id FROM first_bound_claim)) <> 'bounded-1' THEN
        RAISE EXCEPTION 'max_items=1 claim exceeded its bound or lost pending work: %',
            remaining;
    END IF;
END
$first_bound$;
CREATE TEMP TABLE second_bound_claim AS
SELECT * FROM pgreact.claim('bounded-2', 1, interval '60 seconds');
DO $second_bound$
DECLARE item record;
BEGIN
    IF (SELECT count(*) FROM second_bound_claim) <> 1
       OR (SELECT episode_id FROM first_bound_claim)
          = (SELECT episode_id FROM second_bound_claim)
       OR EXISTS (
           SELECT 1 FROM pgreact_internal.agenda
           WHERE state IN ('PENDING','RETRY_WAIT')
             AND available_at <= clock_timestamp()
             AND rule_version_id = (SELECT rule_version_id FROM pgreact.rules
                                   WHERE rule_name='maintenance-claim')) THEN
        RAISE EXCEPTION 'second bounded claim is missing, duplicated or stranded';
    END IF;
    FOR item IN
        SELECT episode_id, lease_token, 'bounded-1'::text AS worker_id FROM first_bound_claim
        UNION ALL
        SELECT episode_id, lease_token, 'bounded-2'::text FROM second_bound_claim
    LOOP
        IF pgreact_api.execute(item.episode_id,item.worker_id,item.lease_token)
           <> 'COMPLETED' THEN
            RAISE EXCEPTION 'bounded claim execution did not complete';
        END IF;
    END LOOP;
    IF (SELECT jsonb_agg(to_jsonb(a) ORDER BY id)
        FROM claim_maintenance.actions a WHERE id IN (4,5))
       IS DISTINCT FROM '[{"id":4,"deadline":"2000-01-04T00:00:00+00:00"},{"id":5,"deadline":"2000-01-05T00:00:00+00:00"}]'::jsonb
       OR (SELECT count(*) FROM claim_maintenance.actions WHERE id IN (4,5)) <> 2 THEN
        RAISE EXCEPTION 'bounded claim mutated wrong action population';
    END IF;
END
$second_bound$;
\else
CREATE TABLE claim_maintenance.result AS SELECT jsonb_build_object('upgrade_only',true) AS vector;
\endif
