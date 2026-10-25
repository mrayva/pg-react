\set ON_ERROR_STOP on
-- The MDM cross-key fixture deliberately leaves the visible level lowered to zero.
-- Set up the next-level-2 idle probe through MDM's authorized human control API.
SELECT c.case_key,c.action_revision,COALESCE(c.assigned_queue::text,'') AS assigned_queue,
       c.due_at::text AS due_at,c.manual_assignment_protected,
       to_jsonb(c)::text AS before_case
FROM mdm_steward.policy_cases_v1 c
WHERE c.entity_name='policy_qualification' AND c.status='open'
  AND NOT c.pending_stewardship AND c.opened_at IS NOT NULL
  AND c.due_at < statement_timestamp() AND c.escalation_level=0
  AND 'ESCALATE'=ANY(c.permitted_actions)
  AND NOT EXISTS (SELECT FROM mdm_steward.policy_receipts_v1 r
      WHERE r.case_key=c.case_key AND r.outcome='APPLIED_CONTROL'
        AND r.request_body->>'action'='ESCALATE' AND r.request_body->'arguments'->>'level'='2')
ORDER BY c.case_key LIMIT 1
\gset
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm_steward.set_case_controls(:case_key,NULLIF(:'assigned_queue','')::name,
    :'due_at'::timestamptz,1,:'manual_assignment_protected'::boolean,
    :action_revision,'Disposable idle-test setup after MDM negative fixtures');
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT jsonb_build_object('before',:'before_case'::jsonb,'after',to_jsonb(c))
FROM mdm_steward.policy_cases_v1 c WHERE c.case_key=:case_key;
