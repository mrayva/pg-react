\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';

-- Run only after the real idle MDM ESCALATE has completed. The MDM authority,
-- not the React request key, retains applied-level history across human edits.
CREATE SCHEMA s1_cross_key;
SELECT r.case_key, r.receipt_id::text AS applied_receipt_id,
       pg_catalog.encode(r.request_key, 'hex') AS applied_request_key
FROM mdm_steward.policy_receipts_v1 AS r
WHERE r.request_body->>'policy_revision' = 's1-idle-feasibility'
  AND r.action = 'ESCALATE' AND r.outcome = 'APPLIED_CONTROL'
\gset applied_

SELECT c.case_key, c.review_version, c.definition_version,
       c.publication_revision, c.stewardship_epoch,
       pg_catalog.encode(c.evidence_basis_digest, 'hex') AS evidence_digest,
       c.action_revision, c.escalation_level,
       COALESCE(c.assigned_queue::text, '') AS assigned_queue,
       c.due_at::text AS due_at, c.manual_assignment_protected,
       pg_catalog.to_jsonb(c)::text AS full_case
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key = :applied_case_key
\gset prior_

SELECT b.binding_id::text, b.binding_version,
       pg_catalog.encode(b.policy_digest, 'hex') AS policy_digest
FROM pgreact_mdm.policy_intent_bindings AS b
WHERE b.policy_revision = 's1-idle-feasibility' AND b.enabled
\gset bound_

-- Capture the entire canonical *original applied request* before the human edit.
-- A same-key retry must replay the APPLIED_CONTROL receipt even after the
-- current level is manually lowered; no new case effect is permitted.
SELECT r.binding_id::text AS binding_id,
       (r.request_body->'arguments')::text AS arguments,
       (r.request_body->>'expected_review_version')::bigint AS review_version,
       (r.request_body->>'expected_definition_version')::bigint AS definition_version,
       (r.request_body->>'expected_publication_revision')::bigint AS publication_revision,
       (r.request_body->>'expected_stewardship_epoch')::bigint AS stewardship_epoch,
       (r.request_body->>'expected_action_revision')::bigint AS action_revision,
       r.request_body->>'expected_evidence_basis_digest' AS evidence_digest,
       r.request_body->>'expected_policy_digest' AS policy_digest,
       r.request_body->>'policy_revision' AS policy_revision,
       r.request_body->>'evaluation_ref' AS evaluation_ref,
       r.request_body->>'work_ref' AS work_ref
FROM mdm_steward.policy_receipts_v1 r
WHERE r.receipt_id = :'applied_applied_receipt_id'::uuid
\gset original_

SELECT :prior_case_key = :applied_case_key
   AND :prior_escalation_level = 2
   AND :prior_action_revision > 0
   AND :'prior_due_at'::timestamptz <= pg_catalog.statement_timestamp()
   AND :bound_binding_version > 0
   AND (SELECT pg_catalog.count(*) = 1 FROM mdm_steward.policy_receipts_v1
        WHERE case_key = :applied_case_key AND action = 'ESCALATE'
          AND outcome = 'APPLIED_CONTROL'
          AND control->>'escalation_level' = '2')
   AS precondition_ok
\gset
\if :precondition_ok
\else
\quit 1
\endif

-- Human is separately authenticated and may reduce the visible level.
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT action_revision
FROM mdm_steward.set_case_controls(
    :prior_case_key, NULLIF(:'prior_assigned_queue', '')::name,
    :'prior_due_at'::timestamptz, 1,
    :'prior_manual_assignment_protected'::boolean,
    :prior_action_revision, 'v0.49 test human level reduction'
)
\gset lowered_
RESET ROLE;
RESET SESSION AUTHORIZATION;

SELECT pg_catalog.to_jsonb(c)::text AS full_case, c.action_revision
FROM mdm_steward.policy_cases_v1 AS c
WHERE c.case_key = :prior_case_key
\gset lowered_case_

SELECT pg_catalog.count(*) = 1 AND pg_catalog.bool_and(
           inspection.policy_revision = 's1-idle-feasibility'
           AND inspection.policy_digest = :'bound_policy_digest'
           AND inspection.binding_version = :bound_binding_version
           AND inspection.action = 'ESCALATE'
           AND inspection.delivery_outcome = 'APPLIED_CONTROL'
           AND inspection.mdm_receipt_id = :'applied_applied_receipt_id'::uuid
           AND inspection.mdm_outcome = 'APPLIED_CONTROL'
           AND inspection.requested_escalation_level = 2
           AND inspection.applied_escalation_level = 2
           AND inspection.current_escalation_level = 1
           AND inspection.current_due_at = :'prior_due_at'::timestamptz
           AND inspection.current_case_status = 'open'
           AND inspection.current_manual_assignment_protected = :'prior_manual_assignment_protected'::boolean
           AND inspection.current_pending_stewardship = false
           AND inspection.remediation_state = 'NONE') AS applied_inspection_exact_ok
FROM pgreact_mdm.delivery_inspection_v1 AS inspection
WHERE inspection.mdm_receipt_id = :'applied_applied_receipt_id'::uuid
\gset
\if :applied_inspection_exact_ok
\else
\quit 1
\endif

SELECT :lowered_action_revision = :prior_action_revision + 1
   AND (SELECT pg_catalog.to_jsonb(c)
        FROM mdm_steward.policy_cases_v1 AS c WHERE c.case_key = :prior_case_key)
       = (:'prior_full_case'::jsonb ||
          pg_catalog.jsonb_build_object(
              'escalation_level', 1,
              'action_revision', :lowered_action_revision))
   AS human_reduction_exact_ok
\gset
\if :human_reduction_exact_ok
\else
\quit 1
\endif

-- Two new keys produce durable denials, not a second level-2 effect.
-- Both calls use fresh complete case tokens, the same qualified binding,
-- and the real MDM worker principal with its original session login.
SET SESSION AUTHORIZATION mdm_s1_runtime;
SET ROLE pgreact_mdm_worker;
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'bound_binding_id'::uuid, pg_catalog.decode(pg_catalog.repeat('ec', 32), 'hex'),
    :prior_case_key, 'ESCALATE', '{"level":2}'::jsonb,
    :prior_review_version, :prior_definition_version,
    :prior_publication_revision, :prior_stewardship_epoch,
    pg_catalog.decode(:'prior_evidence_digest', 'hex'),
    :lowered_action_revision, pg_catalog.decode(:'bound_policy_digest', 'hex'),
    's1-idle-feasibility', 'cross-key-ec', 'cross-key-work-ec'
)
\gset denied_ec_
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'bound_binding_id'::uuid, pg_catalog.decode(pg_catalog.repeat('ed', 32), 'hex'),
    :prior_case_key, 'ESCALATE', '{"level":2}'::jsonb,
    :prior_review_version, :prior_definition_version,
    :prior_publication_revision, :prior_stewardship_epoch,
    pg_catalog.decode(:'prior_evidence_digest', 'hex'),
    :lowered_action_revision, pg_catalog.decode(:'bound_policy_digest', 'hex'),
    's1-idle-feasibility', 'cross-key-ed', 'cross-key-work-ed'
)
\gset denied_ed_
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'bound_binding_id'::uuid, pg_catalog.decode(pg_catalog.repeat('ec', 32), 'hex'),
    :prior_case_key, 'ESCALATE', '{"level":2}'::jsonb,
    :prior_review_version, :prior_definition_version,
    :prior_publication_revision, :prior_stewardship_epoch,
    pg_catalog.decode(:'prior_evidence_digest', 'hex'),
    :lowered_action_revision, pg_catalog.decode(:'bound_policy_digest', 'hex'),
    's1-idle-feasibility', 'cross-key-ec', 'cross-key-work-ec'
)
\gset replay_ec_
SELECT receipt_id, outcome, reason_code, case_key, action_revision, control
FROM mdm_steward.submit_policy_intent(
    :'original_binding_id'::uuid,
    pg_catalog.decode(:'applied_applied_request_key', 'hex'),
    :prior_case_key, 'ESCALATE', :'original_arguments'::jsonb,
    :original_review_version, :original_definition_version,
    :original_publication_revision, :original_stewardship_epoch,
    pg_catalog.decode(:'original_evidence_digest', 'hex'),
    :original_action_revision,
    pg_catalog.decode(:'original_policy_digest', 'hex'),
    :'original_policy_revision', :'original_evaluation_ref', :'original_work_ref'
)
\gset replay_applied_
RESET ROLE;
RESET SESSION AUTHORIZATION;

-- Compare each complete canonical request and persisted terminal receipt;
-- the same-key retry returns the identical receipt, not a third denial row.
SELECT :'denied_ec_outcome' = 'ACTION_DENIED'
   AND :'denied_ed_outcome' = 'ACTION_DENIED'
   AND :'denied_ec_reason_code' = 'ESCALATION_LEVEL_ALREADY_APPLIED'
   AND :'denied_ed_reason_code' = 'ESCALATION_LEVEL_ALREADY_APPLIED'
   AND :denied_ec_action_revision = :lowered_action_revision
   AND :denied_ed_action_revision = :lowered_action_revision
   AND :'denied_ec_receipt_id'::uuid <> :'denied_ed_receipt_id'::uuid
   AND :'denied_ec_receipt_id'::uuid = :'replay_ec_receipt_id'::uuid
   AND :'replay_applied_receipt_id'::uuid = :'applied_applied_receipt_id'::uuid
   AND :'replay_applied_outcome' = 'APPLIED_CONTROL'
   AND :'replay_applied_reason_code' = 'CONTROL_APPLIED'
   AND :replay_applied_case_key = :prior_case_key
   AND :replay_applied_action_revision = :prior_action_revision
   AND (:'replay_applied_control'::jsonb ->> 'escalation_level') = '2'
   AND (:'replay_applied_control'::jsonb ->> 'due_at') = :'prior_due_at'
   AND :'denied_ec_outcome' = :'replay_ec_outcome'
   AND :'denied_ec_reason_code' = :'replay_ec_reason_code'
   AND :'denied_ec_control'::jsonb = :'replay_ec_control'::jsonb
   AND :'denied_ec_control'::jsonb = :'denied_ed_control'::jsonb
   AND (SELECT pg_catalog.to_jsonb(c) = :'lowered_case_full_case'::jsonb
        FROM mdm_steward.policy_cases_v1 c WHERE case_key = :prior_case_key)
   AND (SELECT pg_catalog.count(*) = 2 AND pg_catalog.bool_and(
         r.binding_id = :'bound_binding_id'::uuid
         AND r.binding_version = :bound_binding_version
         AND r.action = 'ESCALATE'
         AND r.case_key = :prior_case_key
         AND r.outcome = 'ACTION_DENIED'
         AND r.reason_code = 'ESCALATION_LEVEL_ALREADY_APPLIED'
         AND r.action_revision = :lowered_action_revision
         AND r.actor::text = 'pgreact_mdm_worker'
         AND r.session_role_name = 'mdm_s1_runtime'
         AND r.selected_role_name = 'pgreact_mdm_worker'
         AND r.resulting_publication_revision IS NULL
         AND pg_catalog.octet_length(r.request_digest) = 32
         AND r.control = pg_catalog.jsonb_build_object(
             'assigned_queue', NULLIF(:'prior_assigned_queue', ''),
             'due_at', :'prior_due_at',
             'escalation_level', 1,
             'manual_assignment_protected', :'prior_manual_assignment_protected'::boolean)
         AND r.request_body = pg_catalog.jsonb_build_object(
             'action','ESCALATE','arguments',pg_catalog.jsonb_build_object('level',2),
             'binding_id', :'bound_binding_id',
             'case_key', :prior_case_key,
             'evaluation_ref', CASE WHEN r.request_key = pg_catalog.decode(pg_catalog.repeat('ec',32),'hex')
                                   THEN 'cross-key-ec' ELSE 'cross-key-ed' END,
             'expected_action_revision', :lowered_action_revision,
             'expected_definition_version', :prior_definition_version,
             'expected_evidence_basis_digest', :'prior_evidence_digest',
             'expected_policy_digest', :'bound_policy_digest',
             'expected_publication_revision', :prior_publication_revision,
             'expected_review_version', :prior_review_version,
             'expected_stewardship_epoch', :prior_stewardship_epoch,
             'policy_revision', 's1-idle-feasibility',
             'work_ref', CASE WHEN r.request_key = pg_catalog.decode(pg_catalog.repeat('ec',32),'hex')
                              THEN 'cross-key-work-ec' ELSE 'cross-key-work-ed' END))
        FROM mdm_steward.policy_receipts_v1 r
        WHERE r.binding_id = :'bound_binding_id'::uuid
          AND r.request_key IN (
              pg_catalog.decode(pg_catalog.repeat('ec',32),'hex'),
              pg_catalog.decode(pg_catalog.repeat('ed',32),'hex')))
   AND (SELECT pg_catalog.count(*) = 1
        FROM mdm_steward.policy_receipts_v1 r
        WHERE r.case_key = :prior_case_key AND r.action = 'ESCALATE'
          AND r.outcome = 'APPLIED_CONTROL'
          AND r.control->>'escalation_level' = '2'
          AND r.receipt_id = :'applied_applied_receipt_id'::uuid)
    AS human_lower_crosskey_exact_ok
\gset
\if :human_lower_crosskey_exact_ok
\else
\quit 1
\endif
CREATE TABLE s1_cross_key.evidence AS
SELECT pg_catalog.jsonb_build_object(
    'original_applied_receipt_id', :'applied_applied_receipt_id',
    'prior_case', :'prior_full_case'::jsonb,
    'lowered_case', :'lowered_case_full_case'::jsonb,
    'denial_receipts', (SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(r) ORDER BY r.request_key)
        FROM mdm_steward.policy_receipts_v1 r
        WHERE r.binding_id = :'bound_binding_id'::uuid
          AND r.request_key IN (
              pg_catalog.decode(pg_catalog.repeat('ec',32),'hex'),
              pg_catalog.decode(pg_catalog.repeat('ed',32),'hex'))),
    'replayed_receipt_id', :'replay_ec_receipt_id',
    'replayed_original_applied_receipt_id', :'replay_applied_receipt_id',
    'exact', true
) AS vector;
\echo PASS: human level reduction, two fresh keys denied, original applied receipt replayed after edit, denial replay exact
