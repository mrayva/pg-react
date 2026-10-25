\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- Runs after real recurrence, its level-2 APPLIED_CONTROL receipt, and
-- PostgreSQL restart/no-replay. The test binding has an authorized hard
-- maximum of 2. A new level-3 proposal is next in sequence but out of bounds.
CREATE SCHEMA s1_maximum;
SELECT (e.vector->>'new_case_key')::bigint AS case_key,
       (e.vector->>'old_case_key')::bigint AS old_case_key
FROM s1_recurrence.evidence e
\gset target_
SELECT c.case_key,c.review_version,c.definition_version,
       c.publication_revision,c.stewardship_epoch,
       encode(c.evidence_basis_digest,'hex') AS evidence_digest,
       c.action_revision,c.escalation_level,c.due_at::text AS due_at,
       to_jsonb(c)::text AS case_state
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key=:target_case_key
\gset current_
SELECT b.binding_id::text AS binding_id, b.binding_version,
       b.max_escalation_level AS maximum,
       encode(b.policy_digest,'hex') AS policy_digest
FROM pgreact_mdm.policy_intent_bindings b
WHERE b.policy_revision='s1-idle-feasibility'
  AND b.entity_name='policy_qualification' AND b.enabled
\gset binding_
SELECT :current_case_key=:target_case_key
   AND :current_escalation_level=2
   AND :binding_maximum=2
   AND :'current_due_at'::timestamptz <= statement_timestamp()
   AND (SELECT count(*)=1 FROM mdm_steward.policy_receipts_v1
        WHERE case_key=:target_case_key AND action='ESCALATE'
          AND outcome='APPLIED_CONTROL'
          AND control->>'escalation_level'='2')
   AS maximum_precondition_ok
\gset
\if :maximum_precondition_ok
\else
\quit 1
\endif
CREATE TABLE s1_maximum.before_receipts AS SELECT
  COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]'::jsonb) AS vector
  FROM mdm_steward.policy_receipts_v1 r;
CREATE TABLE s1_maximum.before_cases AS SELECT
  COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb) AS vector
  FROM mdm_steward.policy_cases_v1 c;
CREATE TABLE s1_maximum.before_adapter AS SELECT jsonb_build_object(
 'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
 'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
 'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
 'core_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
 'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
 'selector',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s)
) AS vector;

SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control,
       resulting_publication_revision
FROM mdm_steward.submit_policy_intent(
    :'binding_binding_id'::uuid,decode(repeat('fb',32),'hex'),
    :target_case_key,'ESCALATE','{"level":3}'::jsonb,
    :current_review_version,:current_definition_version,
    :current_publication_revision,:current_stewardship_epoch,
    decode(:'current_evidence_digest','hex'),:current_action_revision,
    decode(:'binding_policy_digest','hex'),
    's1-idle-feasibility','recurrence-over-max','recurrence-over-max-work')
\gset limited_
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control,
       resulting_publication_revision
FROM mdm_steward.submit_policy_intent(
    :'binding_binding_id'::uuid,decode(repeat('fb',32),'hex'),
    :target_case_key,'ESCALATE','{"level":3}'::jsonb,
    :current_review_version,:current_definition_version,
    :current_publication_revision,:current_stewardship_epoch,
    decode(:'current_evidence_digest','hex'),:current_action_revision,
    decode(:'binding_policy_digest','hex'),
    's1-idle-feasibility','recurrence-over-max','recurrence-over-max-work')
\gset replay_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT :'limited_outcome'='LIMIT_EXCEEDED'
  AND :'limited_reason_code'='ESCALATION_LIMIT'
  AND :limited_case_key=:target_case_key
  AND :limited_action_revision=:current_action_revision
  AND :'limited_receipt_id'::uuid=:'replay_receipt_id'::uuid
  AND :'limited_outcome'=:'replay_outcome'
  AND :'limited_reason_code'=:'replay_reason_code'
  AND :'limited_control'::jsonb=:'replay_control'::jsonb
  AND (SELECT resulting_publication_revision IS NULL
       FROM mdm_steward.policy_receipts_v1
       WHERE binding_id=:'binding_binding_id'::uuid
         AND request_key=decode(repeat('fb',32),'hex'))
  AND (SELECT to_jsonb(c)=:'current_case_state'::jsonb
       FROM mdm_steward.policy_cases_v1 c WHERE case_key=:target_case_key)
  AND (SELECT vector FROM s1_maximum.before_cases)=
      (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb)
       FROM mdm_steward.policy_cases_v1 c)
  AND (SELECT vector FROM s1_maximum.before_adapter)=jsonb_build_object(
     'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
     'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
     'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
     'core_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
     'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
     'selector',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s))
  AND (SELECT count(*)=1 AND bool_and(
      case_key=:target_case_key AND binding_id=:'binding_binding_id'::uuid
      AND binding_version=:binding_binding_version
      AND action='ESCALATE' AND outcome='LIMIT_EXCEEDED'
      AND reason_code='ESCALATION_LIMIT'
      AND action_revision=:current_action_revision
      AND control=:'limited_control'::jsonb
      AND resulting_publication_revision IS NULL
      AND actor='pgreact_mdm_worker'
      AND session_role_name='mdm_s1_runtime'
      AND selected_role_name='pgreact_mdm_worker'
      AND request_body=jsonb_build_object(
        'action','ESCALATE','arguments',jsonb_build_object('level',3),
        'binding_id',:'binding_binding_id','case_key',:target_case_key,
        'evaluation_ref','recurrence-over-max',
        'work_ref','recurrence-over-max-work',
        'expected_review_version',:current_review_version,
        'expected_definition_version',:current_definition_version,
        'expected_publication_revision',:current_publication_revision,
        'expected_stewardship_epoch',:current_stewardship_epoch,
        'expected_evidence_basis_digest',:'current_evidence_digest',
        'expected_action_revision',:current_action_revision,
        'expected_policy_digest',:'binding_policy_digest',
        'policy_revision','s1-idle-feasibility')
      AND request_digest=pgreact_mdm.intent_request_digest(request_body))
      FROM mdm_steward.policy_receipts_v1
      WHERE binding_id=:'binding_binding_id'::uuid
      AND request_key=decode(repeat('fb',32),'hex'))
  AND (SELECT count(*)=1
       FROM mdm_steward.policy_receipts_v1 r
       WHERE r.case_key=:target_case_key AND r.action='ESCALATE'
         AND r.outcome='APPLIED_CONTROL' AND r.control->>'escalation_level'='2')
  AND (SELECT vector FROM s1_maximum.before_receipts)=
      (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]'::jsonb)
       FROM mdm_steward.policy_receipts_v1 r WHERE r.request_key <> decode(repeat('fb',32),'hex'))
  AS maximum_exact_ok
\gset
\if :maximum_exact_ok
\else
\quit 1
\endif
CREATE TABLE s1_maximum.evidence AS SELECT jsonb_build_object(
 'case_key',:target_case_key,'binding_maximum',:binding_maximum,
 'denied_receipt',(SELECT to_jsonb(r) FROM mdm_steward.policy_receipts_v1 r
                  WHERE binding_id=:'binding_binding_id'::uuid
                    AND request_key=decode(repeat('fb',32),'hex')),
 'replayed_receipt_id',:'replay_receipt_id',
 'state_unchanged',true,'exact',true
) AS vector;
\echo PASS: genuine recurrence bound enforces max level, no duplicate effect and immutable replay
