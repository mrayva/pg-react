\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
BEGIN;

-- Run after the real operator pause and its cold-restart/no-replay proof.
-- Reconciliation requires the exact paused MDM runtime version. Previously
-- denied request keys remain immutable; fresh keys see the active binding.
CREATE SCHEMA s1_resume;
SELECT (e.vector->>'binding_id')::uuid::text AS id,
       (e.vector->>'paused_runtime_version')::bigint AS paused_version,
       (e.vector->>'case_key')::bigint AS case_key,
       (e.vector->'receipt'->>'receipt_id')::uuid::text AS paused_receipt_id
FROM s1_pause.evidence e
\gset prior_
SELECT b.binding_version, b.entity_execution_role::text AS owner_role,
       b.max_escalation_level AS maximum,
       encode(b.policy_digest,'hex') AS policy_digest
FROM pgreact_mdm.policy_intent_bindings b
WHERE b.binding_id=:'prior_id'::uuid
\gset bind_
SELECT c.review_version,c.definition_version,c.publication_revision,
       c.stewardship_epoch,c.action_revision,c.escalation_level,
       encode(c.evidence_basis_digest,'hex') AS evidence_digest
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key=:prior_case_key
\gset case_

SELECT :'bind_owner_role'='mdm_legacy_administrator'
   AND :bind_maximum=2 AND :case_escalation_level=2
   AND :prior_paused_version > 0
   AND (SELECT state='paused' AND runtime_version=:prior_paused_version
        FROM mdm_internal.policy_binding_runtime
        WHERE binding_id=:'prior_id'::uuid)
   AND NOT EXISTS (SELECT 1 FROM pgreact_mdm.policy_intent_runtime
                   WHERE binding_id=:'prior_id'::uuid)
   AND (SELECT outcome='BINDING_PAUSED' AND reason_code='BINDING_PAUSED'
        FROM mdm_steward.policy_receipts_v1
        WHERE receipt_id=:'prior_paused_receipt_id'::uuid)
 AS resume_precondition_ok
\gset
\if :resume_precondition_ok
\else
\quit 1
\endif

CREATE TABLE s1_resume.cases_before AS
SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb) AS vector
FROM mdm_steward.policy_cases_v1 c;
CREATE TABLE s1_resume.receipts_before AS
SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]'::jsonb) AS vector
FROM mdm_steward.policy_receipts_v1 r;
CREATE TABLE s1_resume.react_before AS
SELECT jsonb_build_object(
 'intent_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
 'intent_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
 'rule_work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
 'rule_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
 'business',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
 'selector',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s)
) AS vector;

SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT pgreact_mdm.reconcile_intent_binding(
    :'prior_id'::uuid,:prior_paused_version) AS new_version
\gset active_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT :active_new_version = :prior_paused_version + 1
  AND (SELECT state='active' AND runtime_version=:active_new_version
       FROM mdm_internal.policy_binding_runtime
       WHERE binding_id=:'prior_id'::uuid)
  AND (SELECT runtime_version=:active_new_version
       FROM pgreact_mdm.policy_intent_runtime
       WHERE binding_id=:'prior_id'::uuid)
  AND (SELECT enabled FROM pgreact_mdm.policy_intent_bindings
       WHERE binding_id=:'prior_id'::uuid)
  AS exact_reactivation_ok
\gset
\if :exact_reactivation_ok
\else
\quit 1
\endif

-- A previously BINDING_PAUSED request key must replay its immutable denial
-- even though that same binding is now active.
SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control
FROM mdm_steward.submit_policy_intent(
    :'prior_id'::uuid,decode(repeat('fc',32),'hex'),
    :prior_case_key,'ESCALATE','{"level":3}'::jsonb,
    :case_review_version,:case_definition_version,
    :case_publication_revision,:case_stewardship_epoch,
    decode(:'case_evidence_digest','hex'),:case_action_revision,
    decode(:'bind_policy_digest','hex'),
    's1-idle-feasibility','operator-paused','paused-intent')
\gset replay_pause_

-- The same active binding must separately apply its normal maximum-level
-- rejection to a new request key, not replay the previous paused outcome.
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control
FROM mdm_steward.submit_policy_intent(
    :'prior_id'::uuid,decode(repeat('fd',32),'hex'),
    :prior_case_key,'ESCALATE','{"level":3}'::jsonb,
    :case_review_version,:case_definition_version,
    :case_publication_revision,:case_stewardship_epoch,
    decode(:'case_evidence_digest','hex'),:case_action_revision,
    decode(:'bind_policy_digest','hex'),
    's1-idle-feasibility','operator-resumed','resumed-intent')
\gset resumed_denied_
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control
FROM mdm_steward.submit_policy_intent(
    :'prior_id'::uuid,decode(repeat('fd',32),'hex'),
    :prior_case_key,'ESCALATE','{"level":3}'::jsonb,
    :case_review_version,:case_definition_version,
    :case_publication_revision,:case_stewardship_epoch,
    decode(:'case_evidence_digest','hex'),:case_action_revision,
    decode(:'bind_policy_digest','hex'),
    's1-idle-feasibility','operator-resumed','resumed-intent')
\gset replay_resumed_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT :'replay_pause_receipt_id'::uuid=:'prior_paused_receipt_id'::uuid
  AND :'replay_pause_outcome'='BINDING_PAUSED'
  AND :'replay_pause_reason_code'='BINDING_PAUSED'
  AND :'resumed_denied_outcome'='LIMIT_EXCEEDED'
  AND :'resumed_denied_reason_code'='ESCALATION_LIMIT'
  AND :'resumed_denied_receipt_id'::uuid<>:'prior_paused_receipt_id'::uuid
  AND :'resumed_denied_receipt_id'::uuid=:'replay_resumed_receipt_id'::uuid
  AND :'resumed_denied_outcome'=:'replay_resumed_outcome'
  AND :'resumed_denied_reason_code'=:'replay_resumed_reason_code'
  AND :'resumed_denied_control'::jsonb=:'replay_resumed_control'::jsonb
  AND :resumed_denied_case_key=:prior_case_key
  AND :resumed_denied_action_revision=:case_action_revision
  AND (SELECT vector FROM s1_resume.cases_before)=
      (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]'::jsonb)
       FROM mdm_steward.policy_cases_v1 c)
  AND (SELECT vector FROM s1_resume.react_before)=jsonb_build_object(
    'intent_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),
    'intent_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
    'rule_work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
    'rule_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
    'business',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
    'selector',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s))
  AND (SELECT vector FROM s1_resume.receipts_before)=
      (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]'::jsonb)
       FROM mdm_steward.policy_receipts_v1 r
       WHERE NOT (r.binding_id=:'prior_id'::uuid
                  AND r.request_key=decode(repeat('fd',32),'hex')))
  AND (SELECT count(*)=1 AND bool_and(
      case_key=:prior_case_key
      AND binding_id=:'prior_id'::uuid AND binding_version=:bind_binding_version
      AND action='ESCALATE' AND outcome='LIMIT_EXCEEDED'
      AND reason_code='ESCALATION_LIMIT'
      AND action_revision=:case_action_revision
      AND control=:'resumed_denied_control'::jsonb
      AND actor='pgreact_mdm_worker'
      AND session_role_name='mdm_s1_runtime'
      AND selected_role_name='pgreact_mdm_worker'
      AND resulting_publication_revision IS NULL
      AND request_digest=pgreact_mdm.intent_request_digest(request_body)
      AND request_body=jsonb_build_object(
        'action','ESCALATE','arguments',jsonb_build_object('level',3),
        'binding_id',:'prior_id','case_key',:prior_case_key,
        'evaluation_ref','operator-resumed',
        'work_ref','resumed-intent',
        'expected_review_version',:case_review_version,
        'expected_definition_version',:case_definition_version,
        'expected_publication_revision',:case_publication_revision,
        'expected_stewardship_epoch',:case_stewardship_epoch,
        'expected_evidence_basis_digest',:'case_evidence_digest',
        'expected_action_revision',:case_action_revision,
        'expected_policy_digest',:'bind_policy_digest',
        'policy_revision','s1-idle-feasibility'))
    FROM mdm_steward.policy_receipts_v1
    WHERE binding_id=:'prior_id'::uuid
      AND request_key=decode(repeat('fd',32),'hex'))
  AND (SELECT count(*)=1 FROM mdm_steward.policy_receipts_v1 r
       WHERE r.case_key=:prior_case_key
         AND r.action='ESCALATE' AND r.outcome='APPLIED_CONTROL'
         AND r.control->>'escalation_level'='2')
 AS resume_exact_ok
\gset
\if :resume_exact_ok
\else
\quit 1
\endif

CREATE TABLE s1_resume.evidence AS
SELECT jsonb_build_object(
 'binding_id',:'prior_id',
 'paused_runtime_version',:prior_paused_version,
 'reactivated_runtime_version',:active_new_version,
 'case_key',:prior_case_key,
 'original_paused_receipt_id',:'prior_paused_receipt_id',
 'replayed_paused_receipt_id',:'replay_pause_receipt_id',
 'new_max_denial_receipt',(SELECT to_jsonb(r) FROM mdm_steward.policy_receipts_v1 r
   WHERE binding_id=:'prior_id'::uuid AND request_key=decode(repeat('fd',32),'hex')),
 'replayed_max_denial_receipt_id',:'replay_resumed_receipt_id',
 'exact',true,'cases_and_react_unchanged',true) AS vector;
COMMIT;
\echo PASS: authorized resume restores runtime; old pause denial replays; fresh key obeys active maximum
