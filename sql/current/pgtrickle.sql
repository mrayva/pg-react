-- Exact pg_trickle 0.108.0 and MDM-pinned 0.108.3 compatibility profiles.
--
-- Assumption: integration_capabilities() is a public zero-argument set-returning
-- function whose rows expose capability/name, major(_version), minor(_version),
-- enabled, and optionally status. JSON conversion keeps this boundary independent
-- of the upstream composite type while still rejecting malformed contracts.

CREATE OR REPLACE FUNCTION pgreact_internal.pgtrickle_capability_report(rows jsonb)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
DECLARE row_data jsonb;
    capability_name text;
    major_text text;
    minor_text text;
    major_version integer;
    minor_version integer;
    enabled boolean;
    status text;
    seen text[] := ARRAY[]::text[];
    capabilities jsonb := '{}'::jsonb;
BEGIN
    IF jsonb_typeof(rows) <> 'array' THEN
        RAISE EXCEPTION 'pg-react pg_trickle capability contract must be an array';
    END IF;

    FOR row_data IN SELECT value FROM jsonb_array_elements(rows) LOOP
        IF jsonb_typeof(row_data) <> 'object' THEN
            RAISE EXCEPTION 'pg-react pg_trickle capability row must be an object: %', row_data;
        END IF;
        capability_name := NULLIF(COALESCE(row_data ->> 'capability', row_data ->> 'name'), '');
        major_text := COALESCE(row_data ->> 'major', row_data ->> 'major_version');
        minor_text := COALESCE(row_data ->> 'minor', row_data ->> 'minor_version');
        IF capability_name IS NULL OR major_text IS NULL OR minor_text IS NULL
           OR jsonb_typeof(row_data -> 'enabled') <> 'boolean'
           OR major_text !~ '^[0-9]+$' OR minor_text !~ '^[0-9]+$' THEN
            RAISE EXCEPTION 'pg-react pg_trickle capability row is malformed: %', row_data;
        END IF;
        BEGIN
            major_version := major_text::integer;
            minor_version := minor_text::integer;
        EXCEPTION WHEN numeric_value_out_of_range THEN
            RAISE EXCEPTION 'pg-react pg_trickle capability version is out of range: %', row_data;
        END;
        IF row_data ? 'status' AND jsonb_typeof(row_data -> 'status') <> 'string' THEN
            RAISE EXCEPTION 'pg-react pg_trickle capability status is malformed: %', row_data;
        END IF;
        IF capability_name = ANY(seen) THEN
            RAISE EXCEPTION 'pg-react pg_trickle capability is duplicated: %', capability_name;
        END IF;
        seen := array_append(seen, capability_name);
        enabled := (row_data ->> 'enabled')::boolean;
        status := COALESCE(row_data ->> 'status', row_data -> 'details' ->> 'status',
                           CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END);
        capabilities := capabilities || jsonb_build_object(
            capability_name,
            jsonb_build_object(
                'major', major_version,
                'minor', minor_version,
                'enabled', enabled,
                'status', status,
                'raw', row_data));
    END LOOP;
    RETURN capabilities;
END
$pgtrickle$;

CREATE OR REPLACE FUNCTION pgreact_internal.pgtrickle_integration_status()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
DECLARE installed_version text;
    rows jsonb;
    capabilities jsonb;
    graph jsonb;
    delta jsonb;
    package_qualified boolean;
    capability_qualified boolean;
BEGIN
    SELECT extversion INTO installed_version
    FROM pg_extension WHERE extname = 'pg_trickle';
    IF installed_version IS NULL THEN
        RAISE EXCEPTION 'pg-react requires the pg_trickle extension';
    END IF;

    -- Call only the public API; private pg_trickle catalogs are deliberately out of scope.
    SELECT COALESCE(jsonb_agg(to_jsonb(capability_row)), '[]'::jsonb)
    INTO rows
    FROM pgtrickle.integration_capabilities() AS capability_row;
    capabilities := pgreact_internal.pgtrickle_capability_report(rows);
    graph := capabilities -> 'external_graph_refresh';
    delta := capabilities -> 'output_delta_consumer';
    package_qualified := installed_version IN ('0.108.0', '0.108.3')
        AND current_setting('transaction_isolation') = 'read committed'
        AND COALESCE(current_setting('pg_trickle.enabled', true), '') = 'off'
        AND COALESCE(current_setting('pg_trickle.cdc_mode', true), '') = 'trigger'
        AND COALESCE(current_setting('pg_trickle.differential_max_change_ratio', true), '0')::numeric = 1.0;
    capability_qualified := graph IS NOT NULL
        AND (graph ->> 'major')::integer = 1
        AND (graph ->> 'minor')::integer = 2
        AND (graph ->> 'enabled')::boolean
        AND graph ->> 'status' = 'stable'
        AND (delta IS NULL OR (
            (delta ->> 'major')::integer = 1
            AND (delta ->> 'minor')::integer = 1
            AND delta ->> 'status' = 'stable'));
    RETURN jsonb_build_object(
        'extension_version', installed_version,
        'package_qualified', package_qualified,
        'capabilities_qualified', capability_qualified,
        'qualified', package_qualified AND capability_qualified,
        'coordination_mode', CASE
            WHEN graph IS NULL OR (graph ->> 'major')::integer <> 1 THEN 'UNSUPPORTED'
            WHEN (graph ->> 'enabled')::boolean
                AND graph ->> 'status' = 'stable' THEN 'LEGACY_EXPLICIT'
            ELSE 'GRAPH_V1_REQUIRED'
        END,
        'graph_v1_used', false,
        'delta_v1_used', false,
        'scheduler_expected', 'off',
        'cdc_expected', 'trigger',
        'capabilities', capabilities);
END
$pgtrickle$;

CREATE OR REPLACE FUNCTION pgreact_internal.require_pgtrickle_runtime()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
DECLARE status jsonb := pgreact_internal.pgtrickle_integration_status();
BEGIN
    IF NOT COALESCE((status ->> 'qualified')::boolean, false) THEN
        RAISE EXCEPTION 'pg-react pg_trickle runtime is unsupported: %', status
            USING HINT = 'Use qualified pg_trickle 0.108.0 or 0.108.3 with scheduler off, trigger CDC, differential ratio 1.0, READ COMMITTED, and stable enabled Graph V1.2.';
    END IF;
END
$pgtrickle$;

COMMENT ON FUNCTION pgreact_internal.pgtrickle_integration_status() IS
    'Public pg_trickle 0.108.0/0.108.3 capability report; stable enabled Graph V1.2 is admitted without changing React coordination.';

CREATE OR REPLACE FUNCTION pgreact_internal.assert_m0_compatibility()
RETURNS void
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
BEGIN
    PERFORM pgreact_internal.require_pgtrickle_runtime();
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'pg-react 0.46.0 requires READ COMMITTED';
    END IF;
END
$pgtrickle$;

CREATE OR REPLACE FUNCTION pgreact_internal.pgtrickle_health_findings()
RETURNS SETOF jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
DECLARE status jsonb;
    graph jsonb;
    delta jsonb;
BEGIN
    BEGIN
        status := pgreact_internal.pgtrickle_integration_status();
    EXCEPTION WHEN OTHERS THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_CAPABILITY_DISCOVERY_FAILED', 'severity', 'ERROR',
            'object_identity', 'pg_trickle',
            'message', 'pg-react could not read pg_trickle.integration_capabilities()',
            'hint', 'Install qualified pg_trickle 0.108.0 or 0.108.3 and verify its public capability API.',
            'details', jsonb_build_object('sqlstate', SQLSTATE, 'error', SQLERRM));
        RETURN;
    END;

    graph := status -> 'capabilities' -> 'external_graph_refresh';
    delta := status -> 'capabilities' -> 'output_delta_consumer';
    IF (status ->> 'extension_version') NOT IN ('0.108.0', '0.108.3') THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_RUNTIME_UNSUPPORTED', 'severity', 'ERROR',
            'object_identity', 'pg_trickle',
            'message', format('installed pg_trickle version is %s; pg-react requires qualified 0.108.0 or 0.108.3',
                              COALESCE(status ->> 'extension_version', '<missing>')),
            'hint', 'Use qualified pg_trickle 0.108.0 or 0.108.3 before resuming pg-react coordination.',
            'installed_version', status ->> 'extension_version',
            'expected_version', '0.108.0 or 0.108.3',
            'coordination_mode', status ->> 'coordination_mode');
    END IF;
    IF COALESCE(current_setting('pg_trickle.enabled', true), '') <> 'off' THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_SCHEDULER_ENABLED', 'severity', 'ERROR',
            'object_identity', 'pg_trickle.enabled',
            'message', 'pg_trickle automatic scheduling is enabled',
            'hint', 'Set pg_trickle.enabled=off so pg-react owns the explicit refresh boundary.');
    END IF;
    IF COALESCE(current_setting('pg_trickle.cdc_mode', true), '') <> 'trigger' THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_CDC_UNSUPPORTED', 'severity', 'ERROR',
            'object_identity', 'pg_trickle.cdc_mode',
            'message', 'pg_trickle is not using stable trigger capture',
            'hint', 'Set pg_trickle.cdc_mode=trigger and restart PostgreSQL.');
    END IF;
    IF COALESCE(current_setting('pg_trickle.differential_max_change_ratio', true), '0')::numeric <> 1.0 THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_ADAPTIVE_FULL_REFRESH', 'severity', 'ERROR',
            'object_identity', 'pg_trickle.differential_max_change_ratio',
            'message', 'pg_trickle may fall back to FULL refresh and suppress CDC triggers',
            'hint', 'Set pg_trickle.differential_max_change_ratio=1.0 for coordinated differential refresh.');
    END IF;
    IF graph IS NULL OR (graph ->> 'major')::integer <> 1
       OR (graph ->> 'minor')::integer <> 2
       OR graph ->> 'status' IS DISTINCT FROM 'stable' THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_CAPABILITY_UNSUPPORTED', 'severity', 'ERROR',
            'object_identity', 'external_graph_refresh',
            'message', 'the discovered stable Graph V1.2 capability is missing or unsupported',
            'hint', 'Use qualified pg_trickle 0.108.0 or 0.108.3 with stable external_graph_refresh 1.2.',
            'capability', 'external_graph_refresh',
            'major', graph ->> 'major', 'minor', graph ->> 'minor',
            'enabled', graph -> 'enabled', 'status', graph ->> 'status');
    ELSIF NOT (graph ->> 'enabled')::boolean THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_GRAPH_DISABLED', 'severity', 'ERROR',
            'object_identity', 'external_graph_refresh',
            'message', 'Graph V1.2 is disabled but the optional stewardship adapter requires it',
            'hint', 'Enable stable external_graph_refresh 1.2 before enabling adapter effects.',
            'capability', 'external_graph_refresh', 'major', graph ->> 'major',
            'minor', graph ->> 'minor', 'enabled', graph -> 'enabled',
            'status', graph ->> 'status');
    ELSE
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_GRAPH_AVAILABLE', 'severity', 'INFO',
            'object_identity', 'external_graph_refresh',
            'message', 'Graph V1.2 is available upstream; pg-react retains explicit coordination',
            'hint', 'No action is required; pg-react does not call Graph V1.2.',
            'capability', 'external_graph_refresh', 'major', graph ->> 'major',
            'minor', graph ->> 'minor', 'enabled', graph -> 'enabled',
            'status', graph ->> 'status');
    END IF;
    IF delta IS NOT NULL AND ((delta ->> 'major')::integer <> 1
       OR (delta ->> 'minor')::integer <> 1
       OR delta ->> 'status' IS DISTINCT FROM 'stable') THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_CAPABILITY_UNSUPPORTED', 'severity', 'ERROR',
            'object_identity', 'output_delta_consumer',
            'message', 'the discovered Delta V1.1 capability is unsupported',
            'hint', 'Use qualified pg_trickle 0.108.0 or 0.108.3 with stable output_delta_consumer 1.1.',
            'capability', 'output_delta_consumer',
            'major', delta ->> 'major', 'minor', delta ->> 'minor',
            'enabled', delta -> 'enabled', 'status', delta ->> 'status');
    ELSIF delta IS NULL THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_DELTA_UNAVAILABLE', 'severity', 'INFO',
            'object_identity', 'output_delta_consumer',
            'message', 'Delta V1.1 is unavailable; pg-react does not consume output deltas',
            'hint', 'No action is required for the explicit pg-react path.');
    ELSIF (delta ->> 'enabled')::boolean THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_DELTA_AVAILABLE', 'severity', 'INFO',
            'object_identity', 'output_delta_consumer',
            'message', 'Delta V1.1 is available upstream; pg-react does not consume output deltas',
            'hint', 'No action is required; pg-react retains explicit coordination.',
            'capability', 'output_delta_consumer', 'major', delta ->> 'major',
            'minor', delta ->> 'minor', 'enabled', delta -> 'enabled',
            'status', delta ->> 'status');
    ELSE
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_DELTA_DISABLED', 'severity', 'INFO',
            'object_identity', 'output_delta_consumer',
            'message', 'Delta V1.1 is present but disabled; pg-react does not consume output deltas',
            'hint', 'No action is required for the explicit pg-react path.',
            'capability', 'output_delta_consumer', 'major', delta ->> 'major',
            'minor', delta ->> 'minor', 'enabled', delta -> 'enabled',
            'status', delta ->> 'status');
    END IF;
END
$pgtrickle$;

DO $pgtrickle_compat$
BEGIN
    IF to_regprocedure('pgreact.health_check()') IS NOT NULL
       AND to_regprocedure('pgreact.health_check_m44()') IS NULL THEN
        EXECUTE 'ALTER FUNCTION pgreact.health_check() RENAME TO health_check_m44';
    END IF;
END
$pgtrickle_compat$;

CREATE OR REPLACE FUNCTION pgreact.health_check()
RETURNS TABLE(code text, severity text, object_identity text, message text, hint text)
LANGUAGE SQL
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
    SELECT code, severity, object_identity, message, hint
    FROM pgreact.health_check_m44()
    UNION ALL
    SELECT finding ->> 'code', finding ->> 'severity', finding ->> 'object_identity',
           finding ->> 'message', finding ->> 'hint'
    FROM pgreact_internal.pgtrickle_health_findings() finding
$pgtrickle$;

DO $pgtrickle_compat$
BEGIN
    IF to_regprocedure('pgreact_api.doctor()') IS NOT NULL
       AND to_regprocedure('pgreact_api.doctor_m44()') IS NULL THEN
        EXECUTE 'ALTER FUNCTION pgreact_api.doctor() RENAME TO doctor_m44';
    END IF;
END
$pgtrickle_compat$;

CREATE OR REPLACE FUNCTION pgreact_api.doctor()
RETURNS jsonb
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
    WITH base AS (SELECT pgreact_api.doctor_m44() AS value),
    diagnostics AS (
        SELECT diagnostic
        FROM base, jsonb_array_elements(base.value -> 'diagnostics') diagnostic
        WHERE diagnostic ->> 'code' NOT LIKE '%TRICKLE%'
          AND diagnostic ->> 'code' NOT LIKE 'PGT_%'
    ), combined AS (
        SELECT diagnostic FROM diagnostics
        UNION ALL
        SELECT finding FROM pgreact_internal.pgtrickle_health_findings() finding
    )
    SELECT base.value || jsonb_build_object(
        'diagnostics', COALESCE((SELECT jsonb_agg(diagnostic ORDER BY diagnostic ->> 'code',
                                                                    diagnostic ->> 'object_identity')
                                FROM combined), '[]'::jsonb),
        'status', CASE WHEN EXISTS (
            SELECT 1 FROM combined WHERE diagnostic ->> 'severity' = 'ERROR')
            THEN 'attention' ELSE 'ready' END)
    FROM base
$pgtrickle$;

DO $pgtrickle_compat$
BEGIN
    IF to_regprocedure('pgreact_internal.managed_cycle(integer)') IS NOT NULL
       AND to_regprocedure('pgreact_internal.managed_cycle_m44(integer)') IS NULL THEN
        EXECUTE 'ALTER FUNCTION pgreact_internal.managed_cycle(integer) RENAME TO managed_cycle_m44';
    END IF;
END
$pgtrickle_compat$;

CREATE OR REPLACE FUNCTION pgreact_internal.managed_cycle(process_pid integer)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $pgtrickle$
DECLARE worker text := format('pg-react-managed/%s/%s', current_database(), process_pid);
    pending bigint;
    status jsonb;
BEGIN
    SELECT count(*) INTO pending
    FROM pgreact_internal.agenda job
    WHERE job.state IN ('PENDING', 'LEASED', 'RETRY_WAIT');
    BEGIN
        status := pgreact_internal.pgtrickle_integration_status();
    EXCEPTION WHEN OTHERS THEN
        status := jsonb_build_object(
            'qualified', false, 'extension_version',
            (SELECT extversion FROM pg_extension WHERE extname = 'pg_trickle'),
            'error_code', 'PGT_CAPABILITY_DISCOVERY_FAILED',
            'error', SQLSTATE || ': ' || SQLERRM);
    END;
    IF NOT COALESCE((status ->> 'qualified')::boolean, false) THEN
        INSERT INTO pgreact_internal.managed_processes (
            database_oid, database_name, backend_pid, state, protocol, pending_jobs, detail)
        VALUES ((SELECT oid FROM pg_database WHERE datname = current_database()),
                current_database(), process_pid, 'error', 2, pending,
                'pg_trickle compatibility blocked: ' || status::text)
        ON CONFLICT (database_oid) DO UPDATE
        SET backend_pid = EXCLUDED.backend_pid, state = 'error', protocol = EXCLUDED.protocol,
            pending_jobs = EXCLUDED.pending_jobs, heartbeat_at = clock_timestamp(),
            detail = EXCLUDED.detail;
        RETURN jsonb_build_object(
            'state', 'blocked', 'pending_jobs', pending, 'processed_jobs', 0,
            'compatibility', status);
    END IF;
    IF NOT pg_is_in_recovery()
       AND to_regprocedure('pgreact_mdm.sync_intent_case_identities()') IS NOT NULL THEN
        -- Enroll MDM-owned occurrences before the existing refresh/time frontier.
        PERFORM pg_catalog.pg_advisory_xact_lock(5788046901200000);
        EXECUTE 'SELECT pgreact_mdm.sync_intent_case_identities()';
    END IF;
    RETURN pgreact_internal.managed_cycle_m44(process_pid);
END
$pgtrickle$;
