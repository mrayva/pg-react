\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
SELECT to_regclass('mdm_steward.policy_cases_v1') IS NOT NULL AS mdm_present
\gset
\if :mdm_present
\ir ../../../../integrations/pg-mdm/sql/policy-inputs.sql
\ir ../../../../integrations/pg-mdm/sql/routing.sql
\ir ../../../../integrations/pg-mdm/sql/deadline-preview.sql
\ir ../../../../integrations/pg-mdm/sql/comparison.sql
\ir ../../../../integrations/pg-mdm/sql/typed-flow.sql
\ir ../../../../integrations/pg-mdm/sql/request-store.sql
\ir ../../../../integrations/pg-mdm/sql/intent-worker.sql
SELECT pgreact_mdm.publish_intent_package('upgrade-rollback',
    '{"routes":[{"entity_name":"policy_qualification","reason_code":"ESTABLISHED_NEEDS_TWO_STRONG_CONNECTIONS","action":"ESCALATE","level":2,"priority":0}]}'::jsonb);
\endif
CREATE SCHEMA upgrade_rollback;
CREATE TABLE upgrade_rollback.candidates(
    subject_id bigint NOT NULL, candidate_id bigint PRIMARY KEY, priority bigint NOT NULL, result text NOT NULL);
INSERT INTO upgrade_rollback.candidates VALUES (1,1001,1,'ready'),(1,1002,2,'fallback');
DO $populate$
DECLARE declaration pgreact_api.declaration; preview jsonb; deployed jsonb; actual jsonb;
BEGIN
    declaration := pgreact.decision('upgrade-rollback', 'upgrade_rollback.candidates',
        'subject_id','candidate_id','priority',ARRAY['result']::name[],statement_timestamp());
    preview := pgreact.preview(declaration);
    deployed := pgreact.deploy(declaration, jsonb_build_object(
        'preview_digest',preview->'summary'->>'preview_digest'));
    IF deployed->>'state' IS DISTINCT FROM 'deployed' THEN
        RAISE EXCEPTION 'upgrade fixture did not deploy: %',deployed;
    END IF;
    PERFORM pgreact.run(statement_timestamp() + interval '1 second');
    SELECT jsonb_agg(jsonb_build_object(
        'subject_key',subject_key,'state',state,'winner_candidate',winner_candidate,
        'winner_priority',winner_priority,'winner_result',winner_result,'claimable',claimable,
        'generation',generation,'revision',revision,'competitors',competitors) ORDER BY subject_key)
    INTO actual FROM pgreact.decision_winners WHERE program_name='upgrade-rollback';
    IF actual IS DISTINCT FROM '[{"subject_key":1,"state":"WINNER","winner_candidate":1001,"winner_priority":1,"winner_result":{"result":"ready"},"claimable":true,"generation":1,"revision":0,"competitors":[{"candidate":1001,"priority":1,"result":{"result":"ready"}},{"candidate":1002,"priority":2,"result":{"result":"fallback"}}]}]'::jsonb THEN
        RAISE EXCEPTION 'upgrade fixture has unexpected complete decision vector: %',actual;
    END IF;
END
$populate$;

CREATE FUNCTION upgrade_rollback.state() RETURNS jsonb LANGUAGE plpgsql AS $state$
DECLARE result jsonb := '{}'::jsonb; relation record; rows jsonb;
BEGIN
    FOR relation IN
        SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('pgreact_internal','pgreact_mdm') AND c.relkind='r'
        ORDER BY n.nspname,c.relname
    LOOP
        EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),''[]'') FROM %I.%I t',
            relation.nspname,relation.relname) INTO rows;
        result := result || jsonb_build_object(relation.nspname||'.'||relation.relname,rows);
    END LOOP;
    IF to_regclass('mdm_steward.policy_cases_v1') IS NOT NULL THEN
        result := result || jsonb_build_object(
            'mdm_cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c),
            'mdm_receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM mdm_steward.policy_receipts_v1 r));
    END IF;
    RETURN result;
END
$state$;
CREATE FUNCTION upgrade_rollback.api() RETURNS jsonb LANGUAGE SQL AS $api$
    SELECT jsonb_agg(jsonb_build_object(
        'identity',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),
        'acl',p.proacl::text,'definition',pg_get_functiondef(p.oid)) ORDER BY p.oid::regprocedure::text)
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname IN ('pgreact','pgreact_api','pgreact_internal','pgreact_mdm') AND p.prokind='f'
$api$;
CREATE TABLE upgrade_rollback.before_upgrade AS
SELECT upgrade_rollback.state() AS state, upgrade_rollback.api() AS api;
CREATE FUNCTION upgrade_rollback.reject_upgrade() RETURNS event_trigger LANGUAGE plpgsql AS $reject$
BEGIN
    RAISE EXCEPTION 'injected adjacent upgrade failure';
END
$reject$;
CREATE EVENT TRIGGER qualification_upgrade_failure ON ddl_command_end
    WHEN TAG IN ('ALTER EXTENSION') EXECUTE FUNCTION upgrade_rollback.reject_upgrade();
CREATE TABLE upgrade_rollback.evidence(result jsonb NOT NULL);
DO $rollback$
DECLARE failure_state text; failure_message text; actual jsonb;
BEGIN
    BEGIN
        ALTER EXTENSION pg_react UPDATE TO '0.46.1';
        RAISE EXCEPTION 'injected upgrade failure did not fire';
    EXCEPTION WHEN raise_exception THEN
        GET STACKED DIAGNOSTICS failure_state = RETURNED_SQLSTATE, failure_message = MESSAGE_TEXT;
        IF failure_state <> 'P0001' OR failure_message <> 'injected adjacent upgrade failure' THEN RAISE; END IF;
    END;
    actual := jsonb_build_object('version',(SELECT extversion FROM pg_extension WHERE extname='pg_react'),
        'state',upgrade_rollback.state(),'api',upgrade_rollback.api());
    IF actual IS DISTINCT FROM (SELECT jsonb_build_object('version','0.46.0','state',state,'api',api)
                               FROM upgrade_rollback.before_upgrade) THEN
        RAISE EXCEPTION 'failed upgrade changed predecessor version, durable state or callable definitions/privileges: %',actual;
    END IF;
    INSERT INTO upgrade_rollback.evidence VALUES (jsonb_build_object(
        'sqlstate',failure_state,'message',failure_message,'restored',actual));
END
$rollback$;
DROP EVENT TRIGGER qualification_upgrade_failure;
DROP FUNCTION upgrade_rollback.reject_upgrade();
ALTER EXTENSION pg_react UPDATE TO '0.46.1';
DO $preserved$
BEGIN
    IF upgrade_rollback.state() IS DISTINCT FROM (SELECT state FROM upgrade_rollback.before_upgrade)
       OR (SELECT extversion FROM pg_extension WHERE extname='pg_react') <> '0.46.1' THEN
        RAISE EXCEPTION 'successful adjacent upgrade changed populated durable state';
    END IF;
END
$preserved$;
SELECT 'populated adjacent upgrade failure rolled back exactly; retry preserved durable state';
