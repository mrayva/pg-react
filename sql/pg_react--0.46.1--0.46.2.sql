-- Local patch (0.46.2): admit any pg_trickle 0.108.x patch release, not only 0.108.0.
-- The capability, scheduler, CDC and change-ratio gates are unchanged; 0.108.3 reports the
-- same stable Graph V1.2 / Delta V1.1 capabilities that 0.108.0 did.
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
    package_qualified := installed_version ~ '^0\.108\.[0-9]+$'
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
            'hint', 'Install the qualified pg_trickle 0.108.0 release and verify its public capability API.',
            'details', jsonb_build_object('sqlstate', SQLSTATE, 'error', SQLERRM));
        RETURN;
    END;

    graph := status -> 'capabilities' -> 'external_graph_refresh';
    delta := status -> 'capabilities' -> 'output_delta_consumer';
    IF status ->> 'extension_version' IS NULL
       OR status ->> 'extension_version' !~ '^0\.108\.[0-9]+$' THEN
        RETURN NEXT jsonb_build_object(
            'code', 'PGT_RUNTIME_UNSUPPORTED', 'severity', 'ERROR',
            'object_identity', 'pg_trickle',
            'message', format('installed pg_trickle version is %s; pg-react requires 0.108.x',
                              COALESCE(status ->> 'extension_version', '<missing>')),
            'hint', 'Upgrade pg_trickle to 0.108.0 before resuming pg-react coordination.',
            'installed_version', status ->> 'extension_version',
            'expected_version', '0.108.x',
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
            'hint', 'Use pg_trickle 0.108.0 with stable external_graph_refresh 1.2.',
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
            'hint', 'Use pg_trickle 0.108.0 with stable output_delta_consumer 1.1.',
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
