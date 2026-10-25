\set ON_ERROR_STOP on

-- Runs after v0.47.sql; all changed fixture and policy rows roll back.
BEGIN;
SET LOCAL TIME ZONE 'UTC';
CREATE TEMP TABLE routing_api_before AS
SELECT oid, proname, proargtypes, prorettype, proretset, prosecdef, proacl
FROM pg_catalog.pg_proc
WHERE oid IN (
    'pgreact_mdm.route_cases(regclass,text)'::regprocedure,
    'pgreact_mdm.route_cases(regclass,text,text)'::regprocedure);
\ir ../../../../integrations/pg-mdm/sql/routing.sql
DO $reinstall$
DECLARE actual jsonb;
BEGIN
    SELECT jsonb_agg(to_jsonb(p) ORDER BY p.oid) INTO actual
    FROM (
        SELECT oid, proname, proargtypes, prorettype, proretset, prosecdef, proacl
        FROM pg_catalog.pg_proc
        WHERE oid IN (SELECT oid FROM routing_api_before)
    ) AS p;
    IF actual IS DISTINCT FROM (
        SELECT jsonb_agg(to_jsonb(p) ORDER BY p.oid) FROM routing_api_before AS p
    ) THEN
        RAISE EXCEPTION 'adapter reinstall changed legacy function identities, results or privileges: %', actual;
    END IF;
END
$reinstall$;

-- Retain the original independent fixture rows for the three-case clock frontier check.
CREATE TEMP TABLE v049_original_cases AS SELECT * FROM mdm_fixture.policy_cases_v1;
DELETE FROM mdm_fixture.policy_cases_v1 WHERE case_key <> 1;
UPDATE mdm_fixture.policy_cases_v1
SET permitted_actions = ARRAY['ESCALATE'], due_at = '2099-10-02 00:00:00+00',
    manual_assignment_protected = true;
SELECT pgreact_mdm.publish_package('v0.49-time', '{
    "deadline":{"duration_seconds":3600,"min_seconds":60,"max_seconds":86400,"replace_existing_deadline":false},
    "routes":[{"entity_name":"customer","reason_code":"POSSIBLE_DUPLICATE","action":"ESCALATE","level":1,"priority":1}]
}'::jsonb);

DO $test$
DECLARE
    due timestamptz := '2099-10-02 00:00:00+00';
    sample timestamptz;
    actual jsonb;
    expected jsonb;
    source_before jsonb;
    source_after jsonb;
    due_result jsonb := '{
        "case_key":1,"review_id":"40000000-0000-4000-8000-000000000001",
        "policy_revision":"v0.49-time","reason_code":"POSSIBLE_DUPLICATE",
        "current_queue":"general","selected_queue":null,
        "decision":"WINNER","action":"ESCALATE","priority":1,
        "competitors":[{"reason_code":"POSSIBLE_DUPLICATE","entity_name":"customer","queue":null,"priority":1,"action":"ESCALATE","level":1}],
        "explanation":{
            "case_key":1,"review_id":"40000000-0000-4000-8000-000000000001",
            "decision":"WINNER","selected_queue":null,"applicable":true,
            "reason":"best allowed candidate","manual_assignment_protected":true,
            "pending_stewardship":false,
            "competitors":[{"reason_code":"POSSIBLE_DUPLICATE","entity_name":"customer","queue":null,"priority":1,"action":"ESCALATE","level":1}],
            "escalation_level":1,
            "captured_at":"2099-10-02T00:00:00+00:00",
            "due_at":"2099-10-02T00:00:00+00:00",
            "deadline_due":true,
            "current_escalation_level":0,
            "requested_escalation_level":1
        }
    }'::jsonb;
    not_due_result jsonb;
    max_level_result jsonb;
    sample_result jsonb;
BEGIN
    not_due_result := due_result || '{"decision":"INELIGIBLE","action":null,"priority":null}'::jsonb
        || jsonb_build_object('explanation',
            ((due_result -> 'explanation') - 'escalation_level')
            || '{"decision":"INELIGIBLE","reason":"deadline has not been reached","deadline_due":false}'::jsonb);
    SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) INTO source_before
    FROM mdm_fixture.policy_cases_v1 AS c;
    FOREACH sample IN ARRAY ARRAY[
        due - interval '1 microsecond', due, due + interval '1 microsecond',
        '2099-10-01 17:00:00-07'::timestamptz, due, due - interval '1 microsecond'
    ] LOOP
        sample_result := CASE WHEN sample < due THEN not_due_result ELSE due_result END;
        expected := jsonb_build_array(jsonb_set(sample_result,
            '{explanation,captured_at}', to_jsonb(sample), true));
        SELECT jsonb_agg(to_jsonb(r) ORDER BY case_key) INTO actual
        FROM pgreact_mdm.route_cases(
            'mdm_fixture.policy_cases_v1', 'v0.49-time', 'customer', sample) AS r;
        IF actual IS DISTINCT FROM expected THEN
            RAISE EXCEPTION 'explicit route vector at %: expected %, got %', sample, expected, actual;
        END IF;
    END LOOP;

    -- Both legacy signatures retain their complete result shape and statement-time semantics.
    SELECT jsonb_agg(jsonb_set(to_jsonb(r), '{explanation,captured_at}', 'null'::jsonb)
                     ORDER BY case_key) INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time') AS r;
    SELECT jsonb_agg(jsonb_set(to_jsonb(r), '{explanation,captured_at}', 'null'::jsonb)
                     ORDER BY case_key) INTO expected
    FROM pgreact_mdm.route_cases(
        'mdm_fixture.policy_cases_v1', 'v0.49-time', NULL::text, statement_timestamp()) AS r;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'legacy all-entity route vector changed: %', actual;
    END IF;
    SELECT jsonb_agg(jsonb_set(to_jsonb(r), '{explanation,captured_at}', 'null'::jsonb)
                     ORDER BY case_key) INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time', 'customer') AS r;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'legacy entity route vector changed: %', actual;
    END IF;
    SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY case_key), '[]'::jsonb) INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time', 'other', due) AS r;
    IF actual IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'entity filter leaked another entity: %', actual;
    END IF;
    SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) INTO source_after
    FROM mdm_fixture.policy_cases_v1 AS c;
    IF source_after IS DISTINCT FROM source_before THEN
        RAISE EXCEPTION 'route evaluation changed case state: %', source_after;
    END IF;

    FOREACH sample IN ARRAY ARRAY[NULL::timestamptz, 'infinity'::timestamptz, '-infinity'::timestamptz] LOOP
        BEGIN
            PERFORM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time', NULL::text, sample);
            RAISE EXCEPTION 'invalid sample accepted: %', sample;
        EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'MDM_ROUTE_CAPTURE: captured_at must be finite and non-null' THEN RAISE; END IF;
        END;
    END LOOP;

    -- A comparison must use its captured time for routing as well as deadline proposals.
    actual := pgreact_mdm.compare_population('mdm_fixture.policy_cases_v1', 'v0.49-time', 'v0.49-time', due,
        '{"id":"time-boundary","membership":[1],"expected_count":1}'::jsonb);
    expected := jsonb_build_object(
        'state', 'complete', 'read_only', true, 'captured_at', due,
        'policy_revisions', '{"current":"v0.49-time","proposed":"v0.49-time"}'::jsonb,
        'coverage', '{"population_id":"time-boundary","membership":[1],"expected_count":1,"observed_count":1,"partial":false,"snapshot":"one READ COMMITTED statement per read"}'::jsonb,
        'rows', jsonb_build_array(jsonb_build_object('case_key', 1, 'changed', false,
            'current', jsonb_build_object(
                'route', due_result - ARRAY['case_key','review_id','policy_revision','reason_code','current_queue','explanation'],
                'deadline', '{"decision":"INELIGIBLE","proposed_due_at":null,"reason":"SET_DUE_AT is not permitted for this case"}'::jsonb),
            'proposed', jsonb_build_object(
                'route', due_result - ARRAY['case_key','review_id','policy_revision','reason_code','current_queue','explanation'],
                'deadline', '{"decision":"INELIGIBLE","proposed_due_at":null,"reason":"SET_DUE_AT is not permitted for this case"}'::jsonb))));
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'comparison sample vector: expected %, got %', expected, actual;
    END IF;

    -- Already-reached levels remain ineligible, including the largest valid integer.
    UPDATE mdm_fixture.policy_cases_v1 SET escalation_level = 2147483647;
    max_level_result := due_result || '{"decision":"INELIGIBLE","action":null,"priority":null}'::jsonb
        || jsonb_build_object('explanation',
            ((due_result -> 'explanation') - 'escalation_level')
            || '{"decision":"INELIGIBLE","reason":"requested level is not the next permitted level"}'::jsonb);
    max_level_result := jsonb_set(max_level_result,
        '{explanation,current_escalation_level}', to_jsonb(2147483647), true);
    SELECT jsonb_agg(to_jsonb(r) ORDER BY case_key) INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time', 'customer', due) AS r;
    IF actual IS DISTINCT FROM jsonb_build_array(max_level_result) THEN
        RAISE EXCEPTION 'maximum current level vector: %', actual;
    END IF;

    PERFORM pgreact_mdm.publish_package('v0.49-diagnostics', '{
        "deadline":{"duration_seconds":3600,"min_seconds":60,"max_seconds":86400,"replace_existing_deadline":false},
        "routes":[{"entity_name":"customer","reason_code":"POSSIBLE_DUPLICATE","queue":"priority_review","priority":1}]
    }'::jsonb);
    UPDATE mdm_fixture.policy_cases_v1
    SET escalation_level = 0, manual_assignment_protected = true,
        permitted_actions = ARRAY['ASSIGN_QUEUE']::text[];
    SELECT r.explanation INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-diagnostics', 'customer', due) AS r;
    expected := jsonb_build_object(
        'case_key', 1, 'review_id', '40000000-0000-4000-8000-000000000001'::uuid,
        'decision', 'PROTECTED', 'selected_queue', NULL, 'applicable', true,
        'reason', 'manual assignment is protected', 'captured_at', due,
        'due_at', due, 'deadline_due', true, 'current_escalation_level', 0,
        'requested_escalation_level', NULL, 'manual_assignment_protected', true,
        'pending_stewardship', false,
        'competitors', jsonb_build_array(jsonb_build_object(
            'reason_code', 'POSSIBLE_DUPLICATE', 'entity_name', 'customer',
            'queue', 'priority_review', 'priority', 1, 'action', 'ASSIGN_QUEUE')));
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'protected route explanation: expected %, got %', expected, actual;
    END IF;

    UPDATE mdm_fixture.policy_cases_v1
    SET manual_assignment_protected = false, assigned_queue = 'priority_review';
    SELECT r.explanation INTO actual
    FROM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-diagnostics', 'customer', due) AS r;
    expected := jsonb_set(expected, '{decision}', '"NO_OP"'::jsonb);
    expected := jsonb_set(expected, '{reason}', '"selected queue matches current queue"'::jsonb);
    expected := jsonb_set(expected, '{manual_assignment_protected}', 'false'::jsonb);
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'no-op route explanation: expected %, got %', expected, actual;
    END IF;
END
$test$;

-- Three separate case identities evaluated at the exact same authoritative
-- sampled time: one overdue, one due at equality, one not yet due.
-- This is a deterministic case-coverage proof, not managed worker admissions.
INSERT INTO mdm_fixture.policy_cases_v1
SELECT * FROM v049_original_cases WHERE case_key IN (2, 7);
UPDATE mdm_fixture.policy_cases_v1
SET reason_code = 'POSSIBLE_DUPLICATE',
    permitted_actions = ARRAY['ESCALATE']::text[],
    assigned_queue = 'general'::name,
    escalation_level = 0,
    manual_assignment_protected = true,
    status = 'open', pending_stewardship = false,
    due_at = CASE case_key
        WHEN 1 THEN '2099-10-01 23:59:59+00'::timestamptz
        WHEN 2 THEN '2099-10-02 00:00:00+00'::timestamptz
        WHEN 7 THEN '2099-10-02 00:00:01+00'::timestamptz
    END
WHERE case_key IN (1, 2, 7);

DO $three_cases$
DECLARE
    frontier timestamptz := '2099-10-02 00:00:00+00';
    sample timestamptz;
    fixture record;
    eligible boolean;
    oracle jsonb;
    expected jsonb;
    actual jsonb;
    before_cases jsonb;
    after_cases jsonb;
    -- Literal reviewed v0.49 case-1 output: the expected row does not
    -- depend on any output returned by route_cases under test.
    due_result jsonb := '{
        "case_key":1,"review_id":"40000000-0000-4000-8000-000000000001",
        "policy_revision":"v0.49-time","reason_code":"POSSIBLE_DUPLICATE",
        "current_queue":"general","selected_queue":null,
        "decision":"WINNER","action":"ESCALATE","priority":1,
        "competitors":[{"reason_code":"POSSIBLE_DUPLICATE","entity_name":"customer","queue":null,"priority":1,"action":"ESCALATE","level":1}],
        "explanation":{
            "case_key":1,"review_id":"40000000-0000-4000-8000-000000000001",
            "decision":"WINNER","selected_queue":null,"applicable":true,
            "reason":"best allowed candidate","manual_assignment_protected":true,
            "pending_stewardship":false,
            "competitors":[{"reason_code":"POSSIBLE_DUPLICATE","entity_name":"customer","queue":null,"priority":1,"action":"ESCALATE","level":1}],
            "escalation_level":1,
            "captured_at":"2099-10-02T00:00:00+00:00",
            "due_at":"2099-10-01T23:59:59+00:00",
            "deadline_due":true,
            "current_escalation_level":0,
            "requested_escalation_level":1
        }
    }'::jsonb;
    fixture_due timestamptz;
BEGIN
    SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key)
    INTO before_cases FROM mdm_fixture.policy_cases_v1 c;
    FOR sample IN SELECT unnest(ARRAY[
        frontier - interval '1 microsecond',
        frontier,
        frontier + interval '1 second'
    ]) LOOP
        expected := '[]'::jsonb;
        FOR fixture IN SELECT * FROM (VALUES
            (1::bigint, '40000000-0000-4000-8000-000000000001'::uuid),
            (2::bigint, '40000000-0000-4000-8000-000000000002'::uuid),
            (7::bigint, '40000000-0000-4000-8000-000000000007'::uuid)
        ) AS cases(case_key, review_id) ORDER BY case_key LOOP
            oracle := jsonb_set(due_result, '{case_key}', to_jsonb(fixture.case_key));
            oracle := jsonb_set(oracle, '{review_id}', to_jsonb(fixture.review_id));
            oracle := jsonb_set(oracle, '{explanation,case_key}', to_jsonb(fixture.case_key));
            oracle := jsonb_set(oracle, '{explanation,review_id}', to_jsonb(fixture.review_id));
            fixture_due := CASE fixture.case_key
                WHEN 1 THEN frontier - interval '1 second'
                WHEN 2 THEN frontier
                ELSE frontier + interval '1 second'
            END;
            oracle := jsonb_set(oracle, '{explanation,captured_at}', to_jsonb(sample));
            oracle := jsonb_set(oracle, '{explanation,due_at}', to_jsonb(fixture_due));
            eligible := sample >= fixture_due;
            IF NOT eligible THEN
                oracle := oracle || '{"decision":"INELIGIBLE","action":null,"priority":null}'::jsonb
                    || jsonb_build_object('explanation',
                        ((oracle -> 'explanation') - 'escalation_level')
                        || '{"decision":"INELIGIBLE","reason":"deadline has not been reached","deadline_due":false}'::jsonb);
            END IF;
            expected := expected || jsonb_build_array(oracle);
        END LOOP;
        SELECT jsonb_agg(to_jsonb(r) ORDER BY case_key) INTO actual
        FROM pgreact_mdm.route_cases(
            'mdm_fixture.policy_cases_v1', 'v0.49-time', 'customer', sample) AS r;
        IF actual IS DISTINCT FROM expected THEN
            RAISE EXCEPTION 'three-case sampled-time vector at %: expected %, actual %',
                sample, expected, actual;
        END IF;
        SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key)
        INTO after_cases FROM mdm_fixture.policy_cases_v1 c;
        IF after_cases IS DISTINCT FROM before_cases THEN
            RAISE EXCEPTION 'three-case sampled routing mutated business/MDM inputs: %',
                after_cases;
        END IF;
    END LOOP;
END
$three_cases$;

CREATE ROLE pgreact_time_reader NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA pgreact_mdm, mdm_fixture TO pgreact_time_reader;
SET LOCAL ROLE pgreact_time_reader;
DO $privileges$
BEGIN
    BEGIN
        PERFORM pgreact_mdm.route_cases('mdm_fixture.policy_cases_v1', 'v0.49-time', NULL::text,
            '2099-10-02 00:00:00+00'::timestamptz);
        RAISE EXCEPTION 'explicit-time route bypassed source privileges';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM <> 'MDM_INPUT_UNAUTHORIZED: mdm_fixture.policy_cases_v1 is not readable by pgreact_time_reader' THEN
            RAISE;
        END IF;
    END;
END
$privileges$;
RESET ROLE;

ROLLBACK;
SELECT 'v0.49 explicit-time routing and comparison: PASS' AS result;
