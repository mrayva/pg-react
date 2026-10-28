\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- The original MDM E2E fixture opened occurrence 1, resolved it by
-- publication, then reopened the *same issue_key* as occurrence 2.
-- Use both actual MDM case keys, not a synthetic adapter or React generation.
CREATE SCHEMA s1_recurrence;

-- Upstream e2e_policy.sql intentionally DROPS its private e2e_policy_vars
-- helper at the end. Only the MDM-owned public policy cases are authoritative
-- after bootstrap, and those rows survive the foundation -> s1_idle clone.
CREATE VIEW s1_recurrence.authoritative_pair AS
SELECT prior.case_key AS old_key, prior.occurrence AS old_occurrence,
       successor.case_key AS new_key, successor.occurrence AS new_occurrence,
       pg_catalog.encode(prior.issue_key, 'hex') AS issue_digest,
       successor.review_version AS review_version,
       successor.definition_version AS definition_version,
       successor.publication_revision AS publication_revision,
       successor.stewardship_epoch AS stewardship_epoch,
       pg_catalog.encode(successor.evidence_basis_digest, 'hex') AS evidence_digest,
       successor.action_revision AS action_revision,
       successor.escalation_level AS escalation_level,
       COALESCE(successor.assigned_queue::text,'') AS queue,
       COALESCE(successor.due_at::text,'') AS due_at,
       successor.manual_assignment_protected AS protected,
       pg_catalog.to_jsonb(successor)::text AS full_case
FROM mdm_steward.policy_cases_v1 prior
JOIN mdm_steward.policy_cases_v1 successor
  ON successor.entity_name = prior.entity_name
 AND successor.issue_key = prior.issue_key
 AND successor.occurrence = prior.occurrence + 1
WHERE prior.entity_name = 'policy_qualification'
  AND prior.occurrence = 1 AND successor.occurrence = 2
  AND prior.status = 'resolved'
  AND prior.opened_at_source = 'publication'
  AND successor.status = 'open'
  AND successor.case_key > prior.case_key
  AND successor.review_id <> prior.review_id
  AND NOT successor.pending_stewardship
  AND successor.opened_at IS NOT NULL
  AND 'ESCALATE' = ANY(successor.permitted_actions);

-- Do not silently choose one row if the MDM E2E population changes. No
-- synthetic issue identity, human level, or case row is permitted here.
DO $pair$
DECLARE actual_count integer;
BEGIN
    SELECT count(*) INTO actual_count FROM s1_recurrence.authoritative_pair;
    IF actual_count <> 1 THEN
        RAISE EXCEPTION 'MDM_RECURRENCE_FIXTURE: expected one retained resolved/open occurrence pair, got %; public cases %',
            actual_count,
            (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'case_key', c.case_key, 'occurrence', c.occurrence,
                'issue_key', encode(c.issue_key, 'hex'),
                'status', c.status, 'pending', c.pending_stewardship,
                'opened_at_source', c.opened_at_source,
                'permitted_actions', c.permitted_actions)
                ORDER BY c.case_key), '[]'::jsonb)
             FROM mdm_steward.policy_cases_v1 c
             WHERE c.entity_name = 'policy_qualification');
    END IF;
END
$pair$;
SELECT * FROM s1_recurrence.authoritative_pair
\gset occurrence_

SELECT :occurrence_old_key <> :occurrence_new_key
   AND :occurrence_new_key > :occurrence_old_key
   AND :occurrence_old_occurrence = 1
   AND :occurrence_new_occurrence = 2
   AND :occurrence_new_key <> (SELECT case_key FROM s1_audit.source)
   AND :occurrence_action_revision > 0
   AND (SELECT count(*) = 1 FROM mdm_steward.policy_cases_v1
        WHERE case_key = :occurrence_old_key AND status = 'resolved')
   AND (SELECT count(*) = 0 FROM mdm_steward.policy_receipts_v1
        WHERE case_key = :occurrence_new_key AND action = 'ESCALATE'
          AND outcome = 'APPLIED_CONTROL' AND control->>'escalation_level' = '2')
   AS recurrence_precondition_ok
\gset
\if :recurrence_precondition_ok
\else
\quit 1
\endif

SELECT b.binding_id::text AS id, b.binding_version AS version,
       pg_catalog.encode(b.policy_digest,'hex') AS digest
FROM pgreact_mdm.policy_intent_bindings b
WHERE b.policy_revision='s1-idle-feasibility'
  AND b.enabled AND b.entity_name='policy_qualification'
  AND b.max_escalation_level >= 2
\gset binding_

CREATE TABLE s1_recurrence.old_case AS
SELECT pg_catalog.to_jsonb(c) AS vector FROM mdm_steward.policy_cases_v1 c
WHERE case_key = :occurrence_old_key;
CREATE TABLE s1_recurrence.old_receipts AS
SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(r)
       ORDER BY created_at,receipt_id),'[]'::jsonb) AS vector
FROM mdm_steward.policy_receipts_v1 r WHERE case_key = :occurrence_old_key;
CREATE TABLE s1_recurrence.before_new AS
SELECT pg_catalog.to_jsonb(c) AS vector FROM mdm_steward.policy_cases_v1 c
WHERE case_key = :occurrence_new_key;

-- Give this genuinely new occurrence a due level-1 control through the
-- authorized entity-role API. No business source or issue history changes.
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT action_revision
FROM mdm_steward.set_case_controls(
    :occurrence_new_key, NULLIF(:'occurrence_queue','')::name,
    pg_catalog.statement_timestamp() - INTERVAL '1 hour',
    1, :'occurrence_protected'::boolean, :occurrence_action_revision,
    'v0.49 genuine recurrence due-time fixture')
\gset prepared_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT c.review_version AS review_version, c.definition_version AS definition_version,
       c.publication_revision AS publication_revision,
       c.stewardship_epoch AS stewardship_epoch,
       pg_catalog.encode(c.evidence_basis_digest,'hex') AS evidence_digest,
       c.action_revision AS action_revision, c.due_at::text AS due_at,
       pg_catalog.to_jsonb(c)::text AS full_case
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key = :occurrence_new_key
\gset prepared_

SELECT :prepared_action_revision = :occurrence_action_revision + 1
   AND :'prepared_full_case'::jsonb =
       (SELECT vector FROM s1_recurrence.before_new)
       || jsonb_build_object('due_at',:'prepared_due_at'::timestamptz,
          'escalation_level',1,'action_revision',:prepared_action_revision)
   AND :'prepared_due_at'::timestamptz <= pg_catalog.statement_timestamp()
   AS recurrence_prepared_exact_ok
\gset
\if :recurrence_prepared_exact_ok
\else
\quit 1
\endif

-- A genuinely new occurrence must be eligible independently of the
-- prior resolved occurrence and must retain its own request identity.
SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control,
       resulting_publication_revision
FROM mdm_steward.submit_policy_intent(
    :'binding_id'::uuid,decode(repeat('fa',32),'hex'),
    :occurrence_new_key,'ESCALATE','{"level":2}'::jsonb,
    :prepared_review_version,:prepared_definition_version,
    :prepared_publication_revision,:prepared_stewardship_epoch,
    decode(:'prepared_evidence_digest','hex'),:prepared_action_revision,
    decode(:'binding_digest','hex'),
    's1-idle-feasibility','recurrence-new-occurrence','recurrence-new-work')
\gset applied_
SELECT receipt_id,outcome,reason_code,case_key,action_revision,control,
       resulting_publication_revision
FROM mdm_steward.submit_policy_intent(
    :'binding_id'::uuid,decode(repeat('fa',32),'hex'),
    :occurrence_new_key,'ESCALATE','{"level":2}'::jsonb,
    :prepared_review_version,:prepared_definition_version,
    :prepared_publication_revision,:prepared_stewardship_epoch,
    decode(:'prepared_evidence_digest','hex'),:prepared_action_revision,
    decode(:'binding_digest','hex'),
    's1-idle-feasibility','recurrence-new-occurrence','recurrence-new-work')
\gset replay_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT pg_catalog.to_jsonb(c)::text AS full_case
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key = :occurrence_new_key
\gset final_
SELECT :'applied_outcome'='APPLIED_CONTROL'
 AND :'applied_reason_code'='CONTROL_APPLIED'
 AND :applied_case_key=:occurrence_new_key
 AND :applied_action_revision=:prepared_action_revision+1
 AND :'applied_receipt_id'::uuid=:'replay_receipt_id'::uuid
 AND :'applied_outcome'=:'replay_outcome'
 AND :'applied_reason_code'=:'replay_reason_code'
 AND :'applied_control'::jsonb=:'replay_control'::jsonb
 AND :'applied_control'::jsonb=jsonb_build_object(
    'assigned_queue',NULLIF(:'occurrence_queue',''),
    'due_at',:'prepared_due_at','escalation_level',2,
    'manual_assignment_protected',:'occurrence_protected'::boolean)
 AND :'final_full_case'::jsonb=:'prepared_full_case'::jsonb
     || jsonb_build_object('escalation_level',2,
                           'action_revision',:applied_action_revision)
 AND (SELECT pg_catalog.to_jsonb(c)=(SELECT vector FROM s1_recurrence.old_case)
      FROM mdm_steward.policy_cases_v1 c WHERE case_key=:occurrence_old_key)
 AND (SELECT COALESCE(jsonb_agg(to_jsonb(r)
            ORDER BY created_at,receipt_id),'[]'::jsonb)
      FROM mdm_steward.policy_receipts_v1 r WHERE case_key=:occurrence_old_key)
      = (SELECT vector FROM s1_recurrence.old_receipts)
 AND (SELECT count(*)=1 AND bool_and(
      binding_id=:'binding_id'::uuid AND binding_version=:binding_version
      AND case_key=:occurrence_new_key AND action='ESCALATE'
      AND outcome='APPLIED_CONTROL' AND reason_code='CONTROL_APPLIED'
      AND request_key=decode(repeat('fa',32),'hex')
      AND request_body=jsonb_build_object(
        'action','ESCALATE','arguments',jsonb_build_object('level',2),
        'binding_id',:'binding_id','case_key',:occurrence_new_key,
        'evaluation_ref','recurrence-new-occurrence',
        'work_ref','recurrence-new-work',
        'expected_action_revision',:prepared_action_revision,
        'expected_review_version',:prepared_review_version,
        'expected_definition_version',:prepared_definition_version,
        'expected_publication_revision',:prepared_publication_revision,
        'expected_stewardship_epoch',:prepared_stewardship_epoch,
        'expected_evidence_basis_digest',:'prepared_evidence_digest',
        'expected_policy_digest',:'binding_digest',
        'policy_revision','s1-idle-feasibility')
      AND actor='pgreact_mdm_worker'
      AND session_role_name='mdm_s1_runtime'
      AND selected_role_name='pgreact_mdm_worker'
      AND resulting_publication_revision IS NULL
      AND control=:'applied_control'::jsonb
      AND action_revision=:applied_action_revision
      AND octet_length(request_digest)=32
      AND request_digest=pgreact_mdm.intent_request_digest(request_body))
      FROM mdm_steward.policy_receipts_v1
      WHERE binding_id=:'binding_id'::uuid
        AND request_key=decode(repeat('fa',32),'hex'))
 AS recurrence_independent_exact_ok
\gset
\if :recurrence_independent_exact_ok
\else
\quit 1
\endif

CREATE TABLE s1_recurrence.evidence AS SELECT jsonb_build_object(
 'old_case_key',:occurrence_old_key,'new_case_key',:occurrence_new_key,
 'old_case',(SELECT vector FROM s1_recurrence.old_case),
 'new_before',(SELECT vector FROM s1_recurrence.before_new),
 'new_prepared',:'prepared_full_case'::jsonb,
 'new_after',:'final_full_case'::jsonb,
 'receipt',(SELECT to_jsonb(r) FROM mdm_steward.policy_receipts_v1 r
     WHERE request_key=decode(repeat('fa',32),'hex') AND binding_id=:'binding_id'::uuid),
 'same_key_replay',:'replay_receipt_id',
 'old_receipts_unchanged',true,
 'exact',true
) AS vector;
\echo PASS: genuine same-issue new MDM occurrence independently applies level 2, original occurrence unchanged
