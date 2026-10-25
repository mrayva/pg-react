\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- Test the optimistic binding-runtime version fence AFTER a valid
-- pause -> cold restart -> authorized resume. A second operator using the
-- old paused version may neither pause nor reconcile the active binding.
CREATE SCHEMA s1_stale_runtime;
SELECT (e.vector->>'binding_id')::uuid AS binding_id,
       (e.vector->>'paused_runtime_version')::bigint AS old_version,
       (e.vector->>'reactivated_runtime_version')::bigint AS active_version
FROM s1_resume.evidence AS e
\gset test_

SELECT :test_active_version > :test_old_version
   AND (SELECT runtime_version = :test_active_version AND state = 'active'
        FROM mdm_internal.policy_binding_runtime
        WHERE binding_id = :'test_binding_id'::uuid)
   AND (SELECT runtime_version = :test_active_version
        FROM pgreact_mdm.policy_intent_runtime
        WHERE binding_id = :'test_binding_id'::uuid)
   AS stale_precondition_ok
\gset
\if :stale_precondition_ok
\else
\quit 1
\endif

CREATE TABLE s1_stale_runtime.before AS
SELECT jsonb_build_object(
  'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')
               FROM pgreact_mdm.policy_intent_bindings b),
  'adapter_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')
                     FROM pgreact_mdm.policy_intent_runtime r),
  'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')
                 FROM mdm_internal.policy_binding_runtime r),
  'cases',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]')
           FROM mdm_steward.policy_cases_v1 c),
  'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]')
              FROM mdm_steward.policy_receipts_v1 r),
  'react_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY binding_id,request_key),'[]')
                    FROM pgreact_mdm.intent_requests q),
  'react_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]')
                    FROM pgreact_mdm.intent_attempts a),
  'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]')
          FROM pgreact.work w),
  'work_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]')
                   FROM pgreact.attempts a),
  'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]')
              FROM public.policy_qualification_source s),
  'selector',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]')
              FROM s1_audit.source s)
) AS vector;

-- SECURITY INVOKER is essential: this fixture records the errors thrown by
-- the public operator functions under the actual non-superuser login/role.
-- The helper is confined to this disposable integration database.
CREATE FUNCTION s1_stale_runtime.reject_old_version(
    binding uuid, stale_version bigint
) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    pause_error text := NULL;
    pause_state text := NULL;
    reconcile_error text := NULL;
    reconcile_state text := NULL;
BEGIN
    BEGIN
        PERFORM pgreact_mdm.pause_intent_binding(binding, stale_version);
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS pause_error = MESSAGE_TEXT,
                                pause_state = RETURNED_SQLSTATE;
    END;
    IF pause_error IS NULL OR
       position('runtime version is stale or binding is replaced' IN pause_error) = 0 THEN
        RAISE EXCEPTION 'STALE_RUNTIME_PAUSE_GATE: unexpected result: SQLSTATE %, message %',
            pause_state, pause_error;
    END IF;

    BEGIN
        PERFORM pgreact_mdm.reconcile_intent_binding(binding, stale_version);
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS reconcile_error = MESSAGE_TEXT,
                                reconcile_state = RETURNED_SQLSTATE;
    END;
    IF reconcile_error IS NULL OR
       position('runtime version is stale or binding is replaced' IN reconcile_error) = 0 THEN
        RAISE EXCEPTION 'STALE_RUNTIME_RESUME_GATE: unexpected result: SQLSTATE %, message %',
            reconcile_state, reconcile_error;
    END IF;
    RETURN jsonb_build_object(
        'pause_sqlstate',pause_state,'pause_message',pause_error,
        'reconcile_sqlstate',reconcile_state,'reconcile_message',reconcile_error,
        'stale_version',stale_version,'both_rejected',true
    );
END
$function$;
REVOKE ALL ON FUNCTION s1_stale_runtime.reject_old_version(uuid,bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA s1_stale_runtime TO mdm_legacy_administrator;
GRANT EXECUTE ON FUNCTION s1_stale_runtime.reject_old_version(uuid,bigint)
    TO mdm_legacy_administrator;

SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT s1_stale_runtime.reject_old_version(
    :'test_binding_id'::uuid, :test_old_version
)::text AS rejection_result
\gset
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT (:'rejection_result'::jsonb->>'both_rejected')::boolean
   AND (:'rejection_result'::jsonb->>'stale_version')::bigint = :test_old_version
   AND :'rejection_result'::jsonb->>'pause_sqlstate' <> '00000'
   AND :'rejection_result'::jsonb->>'reconcile_sqlstate' <> '00000'
   AND (SELECT vector FROM s1_stale_runtime.before)=jsonb_build_object(
      'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')
                  FROM pgreact_mdm.policy_intent_bindings b),
      'adapter_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')
                         FROM pgreact_mdm.policy_intent_runtime r),
      'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')
                     FROM mdm_internal.policy_binding_runtime r),
      'cases',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]')
               FROM mdm_steward.policy_cases_v1 c),
      'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]')
                  FROM mdm_steward.policy_receipts_v1 r),
      'react_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY binding_id,request_key),'[]')
                        FROM pgreact_mdm.intent_requests q),
      'react_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]')
                        FROM pgreact_mdm.intent_attempts a),
      'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]')
              FROM pgreact.work w),
      'work_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]')
                       FROM pgreact.attempts a),
      'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]')
                  FROM public.policy_qualification_source s),
      'selector',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]')
                  FROM s1_audit.source s))
   AND (SELECT runtime_version = :test_active_version AND state = 'active'
        FROM mdm_internal.policy_binding_runtime
        WHERE binding_id=:'test_binding_id'::uuid)
   AND (SELECT runtime_version = :test_active_version
        FROM pgreact_mdm.policy_intent_runtime
        WHERE binding_id=:'test_binding_id'::uuid)
   AS stale_version_exact_ok
\gset
\if :stale_version_exact_ok
\else
\quit 1
\endif

CREATE TABLE s1_stale_runtime.evidence AS
SELECT jsonb_build_object(
    'binding_id',:'test_binding_id',
    'old_version',:test_old_version,
    'active_version',:test_active_version,
    'errors',:'rejection_result'::jsonb,
    'complete_state_unchanged',true,
    'exact',true
) AS vector;
\echo PASS: stale pause/reconcile calls rejected with exact unchanged MDM and React state
