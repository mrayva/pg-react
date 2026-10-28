\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- Audit the newly qualified MDM producer without weakening React's admission gate.
CREATE SCHEMA s1_runtime_gate;
CREATE TABLE s1_runtime_gate.evidence(vector jsonb NOT NULL);
DO $gate$
DECLARE
    compatibility jsonb;
    cycle jsonb;
    run_result jsonb;
    sample timestamptz := '2026-10-19 00:00:00+00';
    frontier timestamptz;
    diagnostic jsonb;
BEGIN
    SELECT jsonb_build_object(
        'extension_version', '0.108.3', 'package_qualified', false,
        'capabilities_qualified', true, 'qualified', false,
        'coordination_mode', 'LEGACY_EXPLICIT',
        'graph_v1_used', false, 'delta_v1_used', false,
        'scheduler_expected', 'off', 'cdc_expected', 'trigger',
        'capabilities', jsonb_object_agg(capability, jsonb_build_object(
            'major', major_version, 'minor', minor_version, 'enabled', enabled,
            'status', details ->> 'status', 'raw', to_jsonb(capability_row))))
    INTO compatibility
    FROM pgtrickle.integration_capabilities() capability_row;
    IF (SELECT extversion FROM pg_extension WHERE extname = 'pg_trickle') <> '0.108.3'
       OR current_setting('pg_trickle.enabled') <> 'off'
       OR current_setting('pg_trickle.cdc_mode') <> 'trigger'
       OR current_setting('pg_trickle.differential_max_change_ratio')::numeric <> 1.0 THEN
        RAISE EXCEPTION 'runtime-gate fixture requires the exact MDM-qualified producer profile';
    END IF;
    cycle := pgreact_api.managed_cycle();
    IF cycle IS DISTINCT FROM jsonb_build_object(
        'state', 'blocked', 'pending_jobs', 0, 'processed_jobs', 0,
        'compatibility', compatibility) THEN
        RAISE EXCEPTION 'managed runtime gate vector differs: %', cycle;
    END IF;
    SELECT pgreact_api.health() ->> 'clock_frontier' INTO frontier;
    run_result := pgreact_api.run(sample);
    IF run_result IS DISTINCT FROM jsonb_build_object(
        'contract_version', 15, 'sampled_time', sample, 'frontier', sample,
        'rules', '[]'::jsonb, 'programs', '[]'::jsonb, 'relations', '[]'::jsonb,
        'policy_sets', '[]'::jsonb, 'jobs_created', 0, 'temporal_changed', 0,
        'clock', jsonb_build_object('sampled_time', sample, 'previous_frontier', frontier,
            'frontier', sample, 'affected_keys', 0, 'affected_rules', 0),
        'decision_analyses', jsonb_build_object('analyses', '[]'::jsonb, 'frontier', sample, 'contract_version', 15),
        'decision_programs', jsonb_build_object('programs', '[]'::jsonb, 'subjects', '[]'::jsonb,
            'frontier', sample, 'contract_version', 14,
            'selection', 'lowest priority wins; an equal best priority is ambiguous'),
        'effective_policies', jsonb_build_object('changed', '[]'::jsonb, 'frontier', sample, 'transitions', 0),
        'parameter_families', jsonb_build_object('families', '[]'::jsonb, 'frontier', sample, 'contract_version', 13),
        'frontier_invariant', jsonb_build_object('sampled_time', sample, 'frontier', sample)) THEN
        RAISE EXCEPTION 'public run gate vector differs: %', run_result;
    END IF;
    SELECT item INTO diagnostic FROM jsonb_array_elements(pgreact_api.doctor()->'diagnostics') item
    WHERE item->>'code' = 'PGT_RUNTIME_UNSUPPORTED';
    IF diagnostic IS DISTINCT FROM jsonb_build_object(
        'code', 'PGT_RUNTIME_UNSUPPORTED', 'severity', 'ERROR',
        'object_identity', 'pg_trickle',
        'message', 'installed pg_trickle version is 0.108.3; pg-react 0.46.0 requires 0.108.0',
        'hint', 'Upgrade pg_trickle to 0.108.0 before resuming pg-react coordination.',
        'installed_version', '0.108.3', 'expected_version', '0.108.0',
        'coordination_mode', 'LEGACY_EXPLICIT') THEN
        RAISE EXCEPTION 'public runtime diagnostic vector differs: %', diagnostic;
    END IF;
    INSERT INTO s1_runtime_gate.evidence VALUES (jsonb_build_object(
        'cycle', cycle, 'run', run_result, 'diagnostic', diagnostic));
END
$gate$;

CREATE TABLE s1_runtime_gate.source(case_key bigint PRIMARY KEY, due_at timestamptz NOT NULL);
INSERT INTO s1_runtime_gate.source VALUES (1, clock_timestamp() + interval '5 seconds');
CREATE VIEW s1_runtime_gate.candidate AS SELECT * FROM s1_runtime_gate.source;
CREATE FUNCTION s1_runtime_gate.deliver(
    context pgreact.activation_context, candidate s1_runtime_gate.candidate
) RETURNS void LANGUAGE SQL AS $callback$ SELECT $callback$;
DO $author$
DECLARE expected_error text;
BEGIN
    SELECT 'pg-react pg_trickle runtime is unsupported: ' || (vector #> '{cycle,compatibility}')::text
    INTO STRICT expected_error FROM s1_runtime_gate.evidence;
    BEGIN
        PERFORM pgreact_api.author_deadline_rule(
            's1-runtime-gate', 's1_runtime_gate.candidate'::regclass,
            'case_key', 'due_at', 'COMMAND',
            's1_runtime_gate.deliver(pgreact.activation_context,s1_runtime_gate.candidate)');
        RAISE EXCEPTION 'unsupported producer unexpectedly admitted a temporal rule';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM IS DISTINCT FROM expected_error THEN RAISE; END IF;
        UPDATE s1_runtime_gate.evidence
        SET vector = vector || jsonb_build_object('author_sqlstate', SQLSTATE, 'author_error', SQLERRM);
    END;
END
$author$;
SELECT 'PASS: exact public unsupported-profile vectors; managed idle acceptance remains STOP' AS result;
