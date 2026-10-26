\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
\if :{?activate}
\else
\set activate false
\endif

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pgreact_mdm.authorized_policy_cases_v1)
       OR EXISTS (SELECT 1 FROM pgreact_mdm.intent_escalation_candidates)
       OR EXISTS (
           SELECT 1 FROM pgreact_mdm.policy_intent_runtime
           WHERE database_oid = (SELECT oid FROM pg_database WHERE datname=current_database())) THEN
        RAISE EXCEPTION 'copied binding is eligible before explicit reconciliation';
    END IF;
END
$guard$;

SET SESSION AUTHORIZATION mdm_s1_runtime;
DO $cycles$
DECLARE result jsonb;
BEGIN
    FOR cycle IN 1..2 LOOP
        result := pgreact_api.managed_cycle();
        IF COALESCE((result->>'processed_jobs')::bigint, 0) <> 0 THEN
            RAISE EXCEPTION 'copied database executed work before activation: %', result;
        END IF;
    END LOOP;
END
$cycles$;
RESET SESSION AUTHORIZATION;

\if :activate
SELECT binding_id, entity_execution_role,
       COALESCE((SELECT runtime_version FROM mdm_internal.policy_binding_runtime r
                 WHERE r.binding_id=b.binding_id),0) AS runtime_version
FROM pgreact_mdm.policy_intent_bindings b
WHERE policy_revision='s1-idle-feasibility' AND enabled
\gset recovery_

GRANT USAGE ON SCHEMA mdm_admin TO :"recovery_entity_execution_role";
GRANT EXECUTE ON FUNCTION mdm_admin.rebind(text) TO :"recovery_entity_execution_role";
SET ROLE :"recovery_entity_execution_role";
SELECT mdm_admin.rebind('policy_qualification');
RESET ROLE;
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE :"recovery_entity_execution_role";
SELECT pgreact_mdm.reconcile_intent_binding(
    :'recovery_binding_id'::uuid, :recovery_runtime_version);
RESET ROLE;
RESET SESSION AUTHORIZATION;

DO $active$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pgreact_mdm.policy_intent_runtime r
        JOIN mdm_internal.policy_binding_runtime m USING(binding_id)
        WHERE r.database_oid = (SELECT oid FROM pg_database WHERE datname=current_database())
          AND m.database_oid=r.database_oid AND m.state='active'
          AND m.automation_role_oid='pgreact_mdm_worker'::regrole
          AND r.worker_role_oid=m.automation_role_oid)
       OR NOT EXISTS (SELECT 1 FROM pgreact_mdm.authorized_policy_cases_v1) THEN
        RAISE EXCEPTION 'explicit reconciliation did not activate the restored binding';
    END IF;
END
$active$;

SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
DO $replay$
DECLARE
    request pgreact_mdm.intent_requests%ROWTYPE;
    expected jsonb;
    actual jsonb;
BEGIN
    SELECT * INTO STRICT request FROM pgreact_mdm.intent_requests
    WHERE policy_revision='s1-idle-feasibility'
    ORDER BY created_at, request_key LIMIT 1;
    SELECT jsonb_build_object(
        'receipt_id',receipt_id,'outcome',outcome,'reason_code',reason_code,
        'case_key',case_key,'action_revision',action_revision,'control',control,
        'resulting_publication_revision',resulting_publication_revision)
    INTO STRICT expected FROM pgreact_mdm.intent_attempts
    WHERE binding_id=request.binding_id AND request_key=request.request_key
      AND receipt_id IS NOT NULL
    ORDER BY attempted_at DESC,attempt_no DESC LIMIT 1;
    IF expected->>'outcome' <> 'APPLIED_CONTROL' THEN
        RAISE EXCEPTION 'recovery requires an original applied receipt: %', expected;
    END IF;
    SELECT to_jsonb(response) INTO STRICT actual
    FROM mdm_steward.submit_policy_intent(
        request.binding_id, request.request_key, request.case_key,
        request.request_body->>'action', request.request_body->'arguments',
        (request.request_body->>'expected_review_version')::bigint,
        (request.request_body->>'expected_definition_version')::bigint,
        (request.request_body->>'expected_publication_revision')::bigint,
        (request.request_body->>'expected_stewardship_epoch')::bigint,
        decode(request.request_body->>'expected_evidence_basis_digest','hex'),
        (request.request_body->>'expected_action_revision')::bigint,
        decode(request.request_body->>'expected_policy_digest','hex'),
        request.policy_revision, request.request_body->>'evaluation_ref', request.work_ref) response;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'restored retry changed the complete original receipt: % / %', expected, actual;
    END IF;
END
$replay$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
\endif
SELECT 'recovery vectors and activation barrier passed';
