\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- Run after the managed idle case has delivered level 2, a human lowered
-- it to level 1, and the pinned producer's concurrent fresh-key denial test.
-- The next human action invalidates a separately captured worker token.
CREATE SCHEMA s1_stale;
-- Obtain the case key from the original applied receipt (never from a
-- mutable React work row).
SELECT c.case_key, c.review_version, c.definition_version,
       c.publication_revision, c.stewardship_epoch,
       pg_catalog.encode(c.evidence_basis_digest,'hex') AS digest,
       c.action_revision, c.escalation_level,
       COALESCE(c.assigned_queue::text,'') AS queue,
       c.due_at::text AS due_at, c.manual_assignment_protected,
       pg_catalog.to_jsonb(c)::text AS full_case
FROM mdm_steward.policy_cases_v1 c
JOIN mdm_steward.policy_receipts_v1 r USING (case_key)
WHERE r.receipt_id = (
    SELECT (vector->>'original_applied_receipt_id')::uuid
    FROM s1_cross_key.evidence)
\gset stale_

SELECT b.binding_id::text AS id, b.binding_version AS version,
       pg_catalog.encode(b.policy_digest,'hex') AS digest
FROM pgreact_mdm.policy_intent_bindings b
WHERE b.policy_revision='s1-idle-feasibility' AND b.enabled
\gset binding_

SELECT :stale_escalation_level = 1 AND :stale_action_revision > 0
   AND :'stale_due_at'::timestamptz <= pg_catalog.statement_timestamp()
   AND (SELECT count(*) = 1
        FROM mdm_steward.policy_receipts_v1
        WHERE case_key=:stale_case_key AND action='ESCALATE'
          AND outcome='APPLIED_CONTROL'
          AND control->>'escalation_level'='2')
   AS precondition_ok
\gset
\if :precondition_ok
\else
\quit 1
\endif

-- Audit only the authorized public state, including immutable React records.
CREATE TABLE s1_stale.before_effects AS
SELECT jsonb_build_object(
    'source',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
    'technical',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s),
    'requests',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests q),
    'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
    'work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
    'core_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a)
) AS value;

-- The case row must change once, through the human-authorized public API.
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT action_revision
FROM mdm_steward.set_case_controls(
    :stale_case_key, NULLIF(:'stale_queue','')::name, :'stale_due_at'::timestamptz,
    :stale_escalation_level, NOT :'stale_manual_assignment_protected'::boolean,
    :stale_action_revision, 'v0.49 human edit invalidates captured work')
\gset human_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT to_jsonb(c)::text AS full_case, action_revision
FROM mdm_steward.policy_cases_v1 c WHERE case_key=:stale_case_key
\gset changed_

SELECT :human_action_revision = :stale_action_revision + 1
  AND (SELECT to_jsonb(c) FROM mdm_steward.policy_cases_v1 c
       WHERE case_key=:stale_case_key)
      = (:'stale_full_case'::jsonb || jsonb_build_object(
            'action_revision', :human_action_revision,
            'manual_assignment_protected', NOT :'stale_manual_assignment_protected'::boolean))
  AS human_change_exact_ok
\gset
\if :human_change_exact_ok
\else
\quit 1
\endif

-- Old captured tokens and current tokens have DIFFERENT terminal reasons:
-- stale case before eligibility/history, and applied-history denial after.
SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'binding_id'::uuid, decode(repeat('f1',32),'hex'),
    :stale_case_key,'ESCALATE','{"level":2}'::jsonb,
    :stale_review_version,:stale_definition_version,
    :stale_publication_revision,:stale_stewardship_epoch,
    decode(:'stale_digest','hex'),:stale_action_revision,
    decode(:'binding_digest','hex'),
    's1-idle-feasibility','stale-before-human','stale-work-before-human')
\gset stale_old_
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'binding_id'::uuid, decode(repeat('f2',32),'hex'),
    :stale_case_key,'ESCALATE','{"level":2}'::jsonb,
    :stale_review_version,:stale_definition_version,
    :stale_publication_revision,:stale_stewardship_epoch,
    decode(:'stale_digest','hex'),:human_action_revision,
    decode(:'binding_digest','hex'),
    's1-idle-feasibility','fresh-after-human','fresh-work-after-human')
\gset stale_fresh_
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'binding_id'::uuid, decode(repeat('f1',32),'hex'),
    :stale_case_key,'ESCALATE','{"level":2}'::jsonb,
    :stale_review_version,:stale_definition_version,
    :stale_publication_revision,:stale_stewardship_epoch,
    decode(:'stale_digest','hex'),:stale_action_revision,
    decode(:'binding_digest','hex'),
    's1-idle-feasibility','stale-before-human','stale-work-before-human')
\gset stale_replay_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT :'stale_old_outcome'='STALE_CASE'
  AND :'stale_old_reason_code'='FRESHNESS_TOKEN_MISMATCH'
  AND :'stale_fresh_outcome'='ACTION_DENIED'
  AND :'stale_fresh_reason_code'='ESCALATION_LEVEL_ALREADY_APPLIED'
  AND :'stale_old_receipt_id'::uuid=:'stale_replay_receipt_id'::uuid
  AND :'stale_old_reason_code'=:'stale_replay_reason_code'
  AND :'stale_old_control'::jsonb=:'stale_replay_control'::jsonb
  AND :'stale_old_receipt_id'::uuid<>:'stale_fresh_receipt_id'::uuid
  AND :stale_old_case_key=:stale_case_key
  AND :stale_fresh_case_key=:stale_case_key
  AND :stale_old_action_revision=:human_action_revision
  AND :stale_fresh_action_revision=:human_action_revision
  AND :'stale_old_control'::jsonb=:'stale_fresh_control'::jsonb
  AND :'stale_old_control'::jsonb = jsonb_build_object(
        'assigned_queue',NULLIF(:'stale_queue',''),
        'due_at',:'stale_due_at',
        'escalation_level',1,
        'manual_assignment_protected',NOT :'stale_manual_assignment_protected'::boolean)
  AND (SELECT to_jsonb(c)=:'changed_full_case'::jsonb
       FROM mdm_steward.policy_cases_v1 c WHERE case_key=:stale_case_key)
  AND (SELECT count(*)=2 AND bool_and(
         outcome = CASE WHEN request_key=decode(repeat('f1',32),'hex')
                         THEN 'STALE_CASE' ELSE 'ACTION_DENIED' END
         AND reason_code=CASE WHEN request_key=decode(repeat('f1',32),'hex')
                         THEN 'FRESHNESS_TOKEN_MISMATCH'
                         ELSE 'ESCALATION_LEVEL_ALREADY_APPLIED' END
         AND case_key=:stale_case_key AND action='ESCALATE'
         AND binding_id=:'binding_id'::uuid AND binding_version=:binding_version
         AND action_revision=:human_action_revision
         AND control=:'stale_old_control'::jsonb
         AND actor='pgreact_mdm_worker'
         AND session_role_name='mdm_s1_runtime'
         AND selected_role_name='pgreact_mdm_worker'
         AND resulting_publication_revision IS NULL
         AND octet_length(request_digest)=32
         AND request_body = jsonb_build_object(
            'action','ESCALATE','arguments',jsonb_build_object('level',2),
            'binding_id',:'binding_id','case_key',:stale_case_key,
            'evaluation_ref',CASE WHEN request_key=decode(repeat('f1',32),'hex')
                   THEN 'stale-before-human' ELSE 'fresh-after-human' END,
            'work_ref',CASE WHEN request_key=decode(repeat('f1',32),'hex')
                   THEN 'stale-work-before-human' ELSE 'fresh-work-after-human' END,
            'expected_action_revision',CASE WHEN request_key=decode(repeat('f1',32),'hex')
                   THEN :stale_action_revision ELSE :human_action_revision END,
            'expected_review_version',:stale_review_version,
            'expected_definition_version',:stale_definition_version,
            'expected_publication_revision',:stale_publication_revision,
            'expected_stewardship_epoch',:stale_stewardship_epoch,
            'expected_evidence_basis_digest',:'stale_digest',
            'expected_policy_digest',:'binding_digest',
            'policy_revision','s1-idle-feasibility')
       ) FROM mdm_steward.policy_receipts_v1
       WHERE binding_id=:'binding_id'::uuid
       AND request_key IN (decode(repeat('f1',32),'hex'),decode(repeat('f2',32),'hex')))
  AND (SELECT count(*)=1 FROM mdm_steward.policy_receipts_v1
       WHERE case_key=:stale_case_key AND action='ESCALATE'
         AND outcome='APPLIED_CONTROL' AND control->>'escalation_level'='2')
  AND (SELECT value FROM s1_stale.before_effects)
      = jsonb_build_object(
        'source',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),
        'technical',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s),
        'requests',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests q),
        'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
        'work',(SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
        'core_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a))
  AS stale_human_edit_exact_ok
\gset
\if :stale_human_edit_exact_ok
\else
\quit 1
\endif

CREATE TABLE s1_stale.evidence AS SELECT jsonb_build_object(
    'case_key', :stale_case_key,
    'case_before', :'stale_full_case'::jsonb,
    'case_after', :'changed_full_case'::jsonb,
    'stale_receipt', (SELECT to_jsonb(r) FROM mdm_steward.policy_receipts_v1 r
        WHERE request_key=decode(repeat('f1',32),'hex') AND binding_id=:'binding_id'::uuid),
    'current_receipt', (SELECT to_jsonb(r) FROM mdm_steward.policy_receipts_v1 r
        WHERE request_key=decode(repeat('f2',32),'hex') AND binding_id=:'binding_id'::uuid),
    'unchanged_adapter_and_sources',true,
    'exact',true
) AS vector;

\echo PASS: stale pre-human tokens denied; fresh previously-applied level denied; original replay exact
