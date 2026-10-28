CREATE OR REPLACE FUNCTION pgreact_mdm.route_cases(
    source_relation regclass,
    target_revision text,
    target_entity text,
    captured_at timestamptz
)
RETURNS TABLE(
    case_key bigint,
    review_id uuid,
    policy_revision text,
    reason_code text,
    current_queue name,
    selected_queue name,
    decision text,
    action text,
    priority integer,
    competitors jsonb,
    explanation jsonb
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    package jsonb;
BEGIN
    IF captured_at IS NULL OR NOT isfinite(captured_at) THEN
        RAISE EXCEPTION 'MDM_ROUTE_CAPTURE: captured_at must be finite and non-null';
    END IF;
    PERFORM pgreact_mdm.assert_source(source_relation);
    IF pgreact_mdm.validate_inputs(source_relation) ->> 'state' <> 'valid' THEN
        RAISE EXCEPTION 'MDM_INPUT_INVALID: %',
            pgreact_mdm.validate_inputs(source_relation) -> 'findings';
    END IF;
    SELECT policy_package
    INTO package
    FROM pgreact_mdm.policy_packages
    WHERE pgreact_mdm.policy_packages.policy_revision = target_revision;
    IF package IS NULL THEN
        RAISE EXCEPTION 'MDM_POLICY_NOT_FOUND: policy revision %', target_revision;
    END IF;
    RETURN QUERY EXECUTE format($query$
        WITH source_rows AS (
            SELECT * FROM %s
            WHERE $3 IS NULL OR entity_name::text = $3
        ), candidates AS (
            SELECT c.case_key, c.review_id, c.reason_code, c.assigned_queue,
                   c.due_at, c.escalation_level,
                   c.manual_assignment_protected, c.pending_stewardship, c.status,
                   jsonb_build_object(
                        'reason_code', route ->> 'reason_code',
                        'entity_name', NULLIF(route ->> 'entity_name', ''),
                        'queue', route ->> 'queue',
                        'priority', COALESCE((route ->> 'priority')::integer, 0),
                        'action', COALESCE(route ->> 'action', 'ASSIGN_QUEUE'))
                     || CASE WHEN COALESCE(route ->> 'action', 'ASSIGN_QUEUE') = 'ESCALATE'
                             THEN jsonb_build_object('level', (route ->> 'level')::integer)
                             ELSE '{}'::jsonb END AS candidate,
                   COALESCE((route ->> 'priority')::integer, 0) AS candidate_priority,
                   CASE WHEN COALESCE(route ->> 'action', 'ASSIGN_QUEUE') = 'ESCALATE'
                        THEN (route ->> 'level')::integer END AS candidate_level,
                   COALESCE(route ->> 'action', 'ASSIGN_QUEUE') AS candidate_action,
                   route ->> 'queue' AS candidate_queue
            FROM source_rows AS c
            CROSS JOIN LATERAL jsonb_array_elements($1 -> 'routes') AS item(route)
            WHERE c.status = 'open'
              AND c.reason_code = route ->> 'reason_code'
              AND (route ->> 'entity_name' IS NULL
                   OR route ->> 'entity_name' = c.entity_name::text)
              AND (NOT ($1 -> 'applicability' ? 'statuses')
                   OR c.status = ANY(ARRAY(
                       SELECT jsonb_array_elements_text($1 -> 'applicability' -> 'statuses'))))
              AND (NOT ($1 -> 'applicability' ? 'reason_codes')
                   OR c.reason_code = ANY(ARRAY(
                       SELECT jsonb_array_elements_text($1 -> 'applicability' -> 'reason_codes'))))
              AND (NOT ($1 -> 'applicability' ? 'entity_names')
                   OR c.entity_name::text = ANY(ARRAY(
                       SELECT jsonb_array_elements_text($1 -> 'applicability' -> 'entity_names'))))
              AND c.permitted_actions @> ARRAY[
                    COALESCE(route ->> 'action', 'ASSIGN_QUEUE')]::text[]
        ), best AS (
            SELECT case_key, min(candidate_priority) AS best_priority
            FROM candidates
            GROUP BY case_key
        ), summarized AS (
            SELECT c.case_key,
                   b.best_priority,
                   count(*) FILTER (WHERE c.candidate_priority = b.best_priority) AS best_count,
                   (array_agg(c.candidate_queue ORDER BY c.candidate_priority,
                       c.candidate_queue, c.candidate ->> 'action') FILTER (
                       WHERE c.candidate_priority = b.best_priority))[1]::name AS best_queue,
                   (array_agg(c.candidate ->> 'action' ORDER BY c.candidate_priority,
                       c.candidate_queue, c.candidate ->> 'action') FILTER (
                       WHERE c.candidate_priority = b.best_priority))[1] AS best_action,
                   (array_agg(c.candidate_level ORDER BY c.candidate_priority,
                       c.candidate_queue, c.candidate ->> 'action') FILTER (
                       WHERE c.candidate_priority = b.best_priority))[1] AS best_level,
                   jsonb_agg(c.candidate ORDER BY c.candidate_priority,
                       c.candidate_queue, c.candidate ->> 'action') AS competitors
            FROM candidates AS c
            JOIN best AS b USING (case_key)
            GROUP BY c.case_key, b.best_priority
        ), decided AS (
            SELECT c.case_key, s.best_priority, s.best_count, s.best_queue,
                   s.best_action, s.best_level, s.competitors,
                   CASE
                       WHEN c.status <> 'open' OR c.pending_stewardship THEN 'INELIGIBLE'
                       WHEN s.case_key IS NULL THEN 'NO_CANDIDATE'
                       WHEN s.best_count > 1 THEN 'AMBIGUOUS'
                       WHEN s.best_action = 'ESCALATE'
                        AND (c.due_at IS NULL OR c.due_at > $4
                             OR s.best_level::bigint <> c.escalation_level::bigint + 1) THEN 'INELIGIBLE'
                       WHEN s.best_action = 'ESCALATE' THEN 'WINNER'
                       WHEN c.manual_assignment_protected THEN 'PROTECTED'
                       WHEN c.assigned_queue IS NOT DISTINCT FROM s.best_queue THEN 'NO_OP'
                       ELSE 'WINNER'
                   END AS decision
            FROM source_rows AS c
            LEFT JOIN summarized AS s USING (case_key)
        )
        SELECT c.case_key, c.review_id, $2, c.reason_code, c.assigned_queue,
               CASE WHEN d.decision = 'WINNER' AND d.best_action = 'ASSIGN_QUEUE'
                    THEN d.best_queue ELSE NULL END,
               d.decision,
               CASE WHEN d.decision = 'WINNER' THEN d.best_action ELSE NULL END,
               CASE WHEN d.decision = 'WINNER' THEN d.best_priority ELSE NULL END,
               COALESCE(d.competitors, '[]'::jsonb),
               jsonb_build_object(
                   'case_key', c.case_key,
                   'review_id', c.review_id,
                    'decision', d.decision,
                    'selected_queue', CASE WHEN d.decision = 'WINNER' AND d.best_action = 'ASSIGN_QUEUE'
                                           THEN d.best_queue ELSE NULL END,
                   'applicable', c.status = 'open' AND NOT c.pending_stewardship,
                   'reason', CASE
                       WHEN c.status <> 'open' THEN 'case is not open'
                       WHEN c.pending_stewardship THEN 'stewardship is pending'
                       WHEN d.decision = 'WINNER' THEN 'best allowed candidate'
                       WHEN d.decision = 'AMBIGUOUS' THEN 'equal best priorities'
                       WHEN d.decision = 'NO_CANDIDATE' THEN 'no applicable route candidate'
                       WHEN d.decision = 'PROTECTED' THEN 'manual assignment is protected'
                       WHEN d.decision = 'NO_OP' THEN 'selected queue matches current queue'
                       WHEN d.best_action = 'ESCALATE' AND c.due_at IS NULL THEN 'no deadline is set'
                       WHEN d.best_action = 'ESCALATE' AND c.due_at > $4 THEN 'deadline has not been reached'
                       WHEN d.best_action = 'ESCALATE' THEN 'requested level is not the next permitted level'
                       ELSE 'case is not eligible for automation'
                   END,
                   'captured_at', $4,
                   'due_at', c.due_at,
                   'deadline_due', c.due_at IS NOT NULL AND c.due_at <= $4,
                   'current_escalation_level', c.escalation_level,
                   'requested_escalation_level', CASE
                       WHEN d.best_action = 'ESCALATE' AND d.best_count = 1 THEN d.best_level
                       ELSE NULL
                   END,
                   'manual_assignment_protected', c.manual_assignment_protected,
                    'pending_stewardship', c.pending_stewardship,
                    'competitors', COALESCE(d.competitors, '[]'::jsonb))
                || CASE WHEN d.decision = 'WINNER' AND d.best_action = 'ESCALATE'
                        THEN jsonb_build_object('escalation_level', d.best_level)
                        ELSE '{}'::jsonb END
        FROM source_rows AS c
        JOIN decided AS d USING (case_key)
        ORDER BY c.case_key
    $query$, source_relation)
    USING package, target_revision, target_entity, captured_at;
END
$function$;

CREATE OR REPLACE FUNCTION pgreact_mdm.route_cases(
    source_relation regclass,
    target_revision text,
    target_entity text
)
RETURNS TABLE(
    case_key bigint,
    review_id uuid,
    policy_revision text,
    reason_code text,
    current_queue name,
    selected_queue name,
    decision text,
    action text,
    priority integer,
    competitors jsonb,
    explanation jsonb
)
LANGUAGE SQL
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT * FROM pgreact_mdm.route_cases($1, $2, $3, statement_timestamp())
$function$;

CREATE OR REPLACE FUNCTION pgreact_mdm.route_cases(
    source_relation regclass,
    target_revision text
)
RETURNS TABLE(
    case_key bigint,
    review_id uuid,
    policy_revision text,
    reason_code text,
    current_queue name,
    selected_queue name,
    decision text,
    action text,
    priority integer,
    competitors jsonb,
    explanation jsonb
)
LANGUAGE SQL
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT * FROM pgreact_mdm.route_cases($1, $2, NULL::text)
$function$;

COMMENT ON FUNCTION pgreact_mdm.route_cases(regclass, text, text) IS
    'v0.47 deterministic MDM routing explanation; ties are ambiguous and never lexical winners';
COMMENT ON FUNCTION pgreact_mdm.route_cases(regclass, text) IS
    'v0.47 deterministic routing across the complete supplied policy relation';
COMMENT ON FUNCTION pgreact_mdm.route_cases(regclass, text, text, timestamptz) IS
    'Explicit-time routing; due_at <= captured_at permits only the configured next escalation level. This read does not authorize MDM delivery.';
