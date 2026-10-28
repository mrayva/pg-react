\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
-- End-of-audit operator pause barrier. No production policy is enabled.
CREATE SCHEMA s1_pause;
SELECT b.binding_id::text AS id, b.binding_version AS version,
       b.entity_execution_role::text AS execution_role,
       encode(b.policy_digest,'hex') AS digest,
       runtime.runtime_version AS runtime_version
FROM pgreact_mdm.policy_intent_bindings b
JOIN pgreact_mdm.policy_intent_runtime runtime USING (binding_id)
WHERE b.policy_revision='s1-idle-feasibility' AND b.enabled
\gset bind_
SELECT (e.vector->>'new_case_key')::bigint AS case_key
FROM s1_recurrence.evidence e
\gset target_
SELECT c.case_key,c.review_version,c.definition_version,c.publication_revision,
       c.stewardship_epoch,encode(c.evidence_basis_digest,'hex') AS evidence_digest,
       c.action_revision,to_jsonb(c)::text AS full_case
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key=:target_case_key
\gset case_
SELECT :'bind_execution_role'='mdm_legacy_administrator'
   AND :bind_runtime_version > 0
   AND :case_case_key=:target_case_key
   AS precondition_ok
\gset
\if :precondition_ok
\else
\quit 1
\endif
CREATE TABLE s1_pause.before_cases AS
SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb) vector
FROM mdm_steward.policy_cases_v1 c;
CREATE TABLE s1_pause.before_effects AS
SELECT jsonb_build_object(
 'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
 'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
 'work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
 'core_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
 'source',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
 'selector',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s)
) AS vector;

-- Authorized, ordered pause; the prior runtime version is a required barrier.
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT pgreact_mdm.pause_intent_binding(:'bind_id'::uuid,:bind_runtime_version)
  AS paused_runtime_version
\gset
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT :paused_runtime_version > :bind_runtime_version
   AND NOT EXISTS (SELECT 1 FROM pgreact_mdm.policy_intent_runtime
                    WHERE binding_id=:'bind_id'::uuid)
   AND (SELECT state='paused' FROM mdm_internal.policy_binding_runtime
        WHERE binding_id=:'bind_id'::uuid)
 AS pause_barrier_ok
\gset
\if :pause_barrier_ok
\else
\quit 1
\endif

-- Fresh key must not bypass the MDM-owned pause even with matching case
-- freshness and otherwise correctly shaped next-level request.
SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control
FROM mdm_steward.submit_policy_intent(
 :'bind_id'::uuid,decode(repeat('fc',32),'hex'),
 :target_case_key,'ESCALATE','{"level":3}'::jsonb,
 :case_review_version,:case_definition_version,
 :case_publication_revision,:case_stewardship_epoch,
 decode(:'case_evidence_digest','hex'),:case_action_revision,
 decode(:'bind_digest','hex'),
 's1-idle-feasibility','operator-paused','paused-intent')
\gset denied_
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control
FROM mdm_steward.submit_policy_intent(
 :'bind_id'::uuid,decode(repeat('fc',32),'hex'),
 :target_case_key,'ESCALATE','{"level":3}'::jsonb,
 :case_review_version,:case_definition_version,
 :case_publication_revision,:case_stewardship_epoch,
 decode(:'case_evidence_digest','hex'),:case_action_revision,
 decode(:'bind_digest','hex'),
 's1-idle-feasibility','operator-paused','paused-intent')
\gset replay_
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT :'denied_outcome'='BINDING_PAUSED'
 AND :'denied_reason_code'='BINDING_PAUSED'
 AND :denied_action_revision=:case_action_revision
 AND :'denied_receipt_id'::uuid=:'replay_receipt_id'::uuid
 AND :'denied_control'::jsonb=:'replay_control'::jsonb
 AND (SELECT vector FROM s1_pause.before_cases)=
     (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb)
      FROM mdm_steward.policy_cases_v1 c)
 AND (SELECT vector FROM s1_pause.before_effects)=jsonb_build_object(
  'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
  'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
  'work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
  'core_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
  'source',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
  'selector',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s))
 AND (SELECT count(*)=1 AND bool_and(
   outcome='BINDING_PAUSED' AND reason_code='BINDING_PAUSED'
   AND case_key=:target_case_key AND action_revision=:case_action_revision
   AND binding_id=:'bind_id'::uuid AND binding_version=:bind_version
   AND action='ESCALATE' AND resulting_publication_revision IS NULL
   AND request_digest=pgreact_mdm.intent_request_digest(request_body)
   AND request_body=jsonb_build_object(
    'action','ESCALATE','arguments',jsonb_build_object('level',3),
    'binding_id',:'bind_id','case_key',:target_case_key,
    'evaluation_ref','operator-paused','work_ref','paused-intent',
    'expected_review_version',:case_review_version,
    'expected_definition_version',:case_definition_version,
    'expected_publication_revision',:case_publication_revision,
    'expected_stewardship_epoch',:case_stewardship_epoch,
    'expected_evidence_basis_digest',:'case_evidence_digest',
    'expected_action_revision',:case_action_revision,
    'expected_policy_digest',:'bind_digest','policy_revision','s1-idle-feasibility'))
 FROM mdm_steward.policy_receipts_v1
 WHERE binding_id=:'bind_id'::uuid AND request_key=decode(repeat('fc',32),'hex'))
 AS pause_receipt_exact_ok
\gset
\if :pause_receipt_exact_ok
\else
\quit 1
\endif
CREATE TABLE s1_pause.evidence AS
SELECT jsonb_build_object('binding_id',:'bind_id','paused_runtime_version',:paused_runtime_version,
 'case_key',:target_case_key,'receipt',(SELECT to_jsonb(r)
 FROM mdm_steward.policy_receipts_v1 r
 WHERE binding_id=:'bind_id'::uuid AND request_key=decode(repeat('fc',32),'hex')),
 'replayed_id',:'replay_receipt_id','state_unchanged',true,'exact',true) vector;
\echo PASS: authorized binding pause barrier rejects fresh worker intent with exact replay
