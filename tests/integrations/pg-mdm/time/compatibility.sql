\set ON_ERROR_STOP on
-- Fault injection is transactional and confined to a disposable database.
BEGIN;
CREATE TEMP TABLE capability_rows AS
SELECT to_jsonb(c) AS row FROM pgtrickle.integration_capabilities() c;
CREATE TEMP TABLE compatibility_results (scenario text, vector jsonb);

CREATE FUNCTION pg_temp.assert_profile(scenario text, version text,
    package_ok boolean, capabilities_ok boolean, mode text DEFAULT 'LEGACY_EXPLICIT')
RETURNS void LANGUAGE plpgsql AS $test$
DECLARE actual jsonb; expected jsonb; cycle jsonb;
BEGIN
    expected := jsonb_build_object(
        'extension_version', version, 'package_qualified', package_ok,
        'capabilities_qualified', capabilities_ok,
        'qualified', package_ok AND capabilities_ok, 'coordination_mode', mode,
        'graph_v1_used', false, 'delta_v1_used', false,
        'scheduler_expected', 'off', 'cdc_expected', 'trigger',
        'capabilities', pgreact_internal.pgtrickle_capability_report(
            (SELECT COALESCE(jsonb_agg(row), '[]') FROM capability_rows)));
    actual := pgreact_internal.pgtrickle_integration_status();
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION '%: expected %, actual %', scenario, expected, actual;
    END IF;
    IF package_ok AND capabilities_ok THEN
        PERFORM pgreact_internal.require_pgtrickle_runtime();
    ELSE
        BEGIN
            PERFORM pgreact_internal.require_pgtrickle_runtime();
            RAISE EXCEPTION 'unsupported profile admitted';
        EXCEPTION WHEN raise_exception THEN
            IF SQLERRM <> 'pg-react pg_trickle runtime is unsupported: ' || expected::text THEN
                RAISE;
            END IF;
        END;
        cycle := pgreact_api.managed_cycle();
        IF cycle IS DISTINCT FROM jsonb_build_object(
            'state', 'blocked', 'pending_jobs', 0, 'processed_jobs', 0,
            'compatibility', expected) THEN
            RAISE EXCEPTION '%: blocked cycle differs: %', scenario, cycle;
        END IF;
    END IF;
    INSERT INTO compatibility_results VALUES (scenario, actual);
END
$test$;

-- Exercise the installed producer first; simulated versions below prove only admission.
SELECT pg_temp.assert_profile('installed-public-contract', extversion, true, true)
FROM pg_extension WHERE extname = 'pg_trickle';
CREATE TEMP TABLE original_capabilities AS TABLE capability_rows;
CREATE OR REPLACE FUNCTION pgtrickle.integration_capabilities()
RETURNS TABLE(capability text, major_version smallint, minor_version smallint,
              enabled boolean, details jsonb)
LANGUAGE sql STABLE AS $stub$
    SELECT r.capability, r.major_version, r.minor_version, r.enabled, r.details
    FROM pg_temp.capability_rows c,
         jsonb_to_record(c.row) AS r(capability text, major_version smallint,
                                    minor_version smallint, enabled boolean, details jsonb)
$stub$;

DO $versions$
DECLARE version text; supported boolean; finding jsonb;
BEGIN
    FOREACH version IN ARRAY ARRAY['0.108.0','0.108.3','0.108.1','0.108.2',
        '0.108.4','0.108.30','0.109.0','0.108.3-dev'] LOOP
        UPDATE pg_extension SET extversion = version WHERE extname = 'pg_trickle';
        supported := version IN ('0.108.0','0.108.3');
        PERFORM pg_temp.assert_profile('version-' || version, version, supported, true);
        SELECT f INTO finding FROM pgreact_internal.pgtrickle_health_findings() f
        WHERE f->>'code' = 'PGT_RUNTIME_UNSUPPORTED';
        IF supported THEN
            IF finding IS NOT NULL THEN RAISE EXCEPTION 'supported version diagnostic: %', finding; END IF;
        ELSIF finding IS DISTINCT FROM jsonb_build_object(
            'code','PGT_RUNTIME_UNSUPPORTED','severity','ERROR','object_identity','pg_trickle',
            'message',format('installed pg_trickle version is %s; pg-react requires qualified 0.108.0 or 0.108.3',version),
            'hint','Use qualified pg_trickle 0.108.0 or 0.108.3 before resuming pg-react coordination.',
            'installed_version',version,'expected_version','0.108.0 or 0.108.3',
            'coordination_mode','LEGACY_EXPLICIT') THEN
            RAISE EXCEPTION 'unsupported version diagnostic differs: %', finding;
        END IF;
    END LOOP;
END
$versions$;
UPDATE pg_extension SET extversion = '0.108.3' WHERE extname = 'pg_trickle';

SET LOCAL pg_trickle.enabled = on;
SELECT pg_temp.assert_profile('scheduler-on','0.108.3',false,true);
SET LOCAL pg_trickle.enabled = off;
SET LOCAL pg_trickle.cdc_mode = auto;
SELECT pg_temp.assert_profile('cdc-auto','0.108.3',false,true);
SET LOCAL pg_trickle.cdc_mode = wal;
SELECT pg_temp.assert_profile('cdc-wal','0.108.3',false,true);
SET LOCAL pg_trickle.cdc_mode = trigger;
SET LOCAL pg_trickle.differential_max_change_ratio = 0.5;
SELECT pg_temp.assert_profile('adaptive-full','0.108.3',false,true);
SET LOCAL pg_trickle.differential_max_change_ratio = 1.0;

DO $capabilities$
DECLARE capability text; patch jsonb; mode text;
BEGIN
    FOREACH capability IN ARRAY ARRAY['external_graph_refresh','output_delta_consumer'] LOOP
        DELETE FROM capability_rows WHERE row->>'capability' = capability;
        PERFORM pg_temp.assert_profile('missing-' || capability,'0.108.3',true,
            capability = 'output_delta_consumer',
            CASE WHEN capability = 'external_graph_refresh' THEN 'UNSUPPORTED' ELSE 'LEGACY_EXPLICIT' END);
        INSERT INTO capability_rows SELECT row FROM original_capabilities WHERE row->>'capability' = capability;
        FOR patch IN SELECT value FROM jsonb_array_elements(
            '[{"major_version":2},{"minor_version":9},{"details":{"status":"experimental"}}]') LOOP
            UPDATE capability_rows c SET row = o.row || patch
            FROM original_capabilities o WHERE c.row->>'capability' = capability
                AND o.row->>'capability' = capability;
            mode := CASE WHEN capability = 'external_graph_refresh' THEN
                CASE WHEN patch ? 'major_version' THEN 'UNSUPPORTED'
                     WHEN patch ? 'details' THEN 'GRAPH_V1_REQUIRED' ELSE 'LEGACY_EXPLICIT' END
                ELSE 'LEGACY_EXPLICIT' END;
            PERFORM pg_temp.assert_profile(capability || '-' || patch::text,'0.108.3',true,false,mode);
        END LOOP;
        UPDATE capability_rows c SET row = o.row || '{"enabled":false}'::jsonb
        FROM original_capabilities o WHERE c.row->>'capability' = capability
            AND o.row->>'capability' = capability;
        PERFORM pg_temp.assert_profile('disabled-' || capability,'0.108.3',true,
            capability = 'output_delta_consumer',
            CASE WHEN capability = 'external_graph_refresh' THEN 'GRAPH_V1_REQUIRED' ELSE 'LEGACY_EXPLICIT' END);
        UPDATE capability_rows c SET row = o.row FROM original_capabilities o
        WHERE c.row->>'capability' = capability AND o.row->>'capability' = capability;
    END LOOP;
END
$capabilities$;

CREATE FUNCTION pg_temp.assert_discovery_failure(scenario text, code text, message text)
RETURNS void LANGUAGE plpgsql AS $test$
DECLARE expected jsonb; actual jsonb;
BEGIN
    BEGIN
        PERFORM pgreact_internal.require_pgtrickle_runtime();
        RAISE EXCEPTION 'invalid discovery admitted';
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> code OR SQLERRM <> message THEN RAISE; END IF;
    END;
    expected := jsonb_build_object('state','blocked','pending_jobs',0,'processed_jobs',0,
        'compatibility',jsonb_build_object('qualified',false,'extension_version','0.108.3',
            'error_code','PGT_CAPABILITY_DISCOVERY_FAILED','error',code || ': ' || message));
    actual := pgreact_api.managed_cycle();
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION '%: discovery failure vector differs: %', scenario, actual;
    END IF;
    INSERT INTO compatibility_results VALUES (scenario, actual);
END
$test$;
INSERT INTO capability_rows SELECT row FROM original_capabilities
WHERE row->>'capability' = 'external_graph_refresh';
SELECT pg_temp.assert_discovery_failure('duplicate-capability','P0001',
    'pg-react pg_trickle capability is duplicated: external_graph_refresh');
TRUNCATE capability_rows;
INSERT INTO capability_rows SELECT row || '{"enabled":null}'::jsonb
FROM original_capabilities WHERE row->>'capability' = 'external_graph_refresh';
SELECT pg_temp.assert_discovery_failure('malformed-capability','P0001',
    'pg-react pg_trickle capability row is malformed: ' ||
    jsonb_build_object('capability',row->>'capability','major_version',row->'major_version',
        'minor_version',row->'minor_version','enabled',null,'details',row->'details')::text)
FROM capability_rows;
ALTER FUNCTION pgtrickle.integration_capabilities() RENAME TO compatibility_hidden_api;
DISCARD PLANS;
SELECT pg_temp.assert_discovery_failure('missing-public-api','42883',
    'function pgtrickle.integration_capabilities() does not exist');

-- Isolation is tested in fresh transactions by the runner; restore every injected fault.
SELECT jsonb_agg(to_jsonb(r) ORDER BY scenario) FROM compatibility_results r;
ROLLBACK;
BEGIN ISOLATION LEVEL REPEATABLE READ;
DO $isolation$
BEGIN
    IF (pgreact_internal.pgtrickle_integration_status()->>'package_qualified')::boolean THEN
        RAISE EXCEPTION 'REPEATABLE READ admitted';
    END IF;
    PERFORM pgreact_api.managed_cycle();
    IF (SELECT state FROM pgreact_internal.managed_processes
        WHERE database_name = current_database()) IS DISTINCT FROM 'error' THEN
        RAISE EXCEPTION 'REPEATABLE READ worker did not fail closed';
    END IF;
END
$isolation$;
ROLLBACK;
BEGIN ISOLATION LEVEL SERIALIZABLE;
DO $isolation$
BEGIN
    IF (pgreact_internal.pgtrickle_integration_status()->>'package_qualified')::boolean THEN
        RAISE EXCEPTION 'SERIALIZABLE admitted';
    END IF;
END
$isolation$;
ROLLBACK;
SELECT 'exact producer/capability/settings admission: PASS';
