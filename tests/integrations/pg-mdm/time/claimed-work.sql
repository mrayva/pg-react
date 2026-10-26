\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
SELECT pgreact_api.pause_rule('s1-callback-failure');
SELECT pgreact_api.pause_rule('s1-future-idle');
CREATE SCHEMA s1_claimed;
CREATE ROLE s1_claimed_reader LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT s1_reader TO s1_claimed_reader;
GRANT USAGE ON SCHEMA pgreact_mdm TO s1_reader;
CREATE TABLE s1_claimed.cases (case_key bigint PRIMARY KEY);
INSERT INTO s1_claimed.cases SELECT case_key FROM s1_audit.source;
INSERT INTO public.policy_qualification_source VALUES
    (1001,'Claimed One','claimed-one@example.test',statement_timestamp()),
    (1002,'Claimed One','claimed-pair@example.test',statement_timestamp()),
    (1003,'Claimed Two','claimed-two@example.test',statement_timestamp()),
    (1004,'Claimed Two','claimed-pair@example.test',statement_timestamp());
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.refresh('policy_qualification','ALLOW');
DO $prepare$
DECLARE c record;
BEGIN
    FOR c IN SELECT case_key,action_revision FROM mdm_steward.policy_cases_v1
             WHERE entity_name='policy_qualification' AND status='open' ORDER BY case_key
    LOOP
        PERFORM mdm_steward.set_case_controls(c.case_key,NULL,
            statement_timestamp()-interval '1 hour',1,false,c.action_revision,
            'Claimed-work deterministic concurrency setup');
    END LOOP;
END
$prepare$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
INSERT INTO s1_claimed.cases SELECT case_key FROM mdm_steward.policy_cases_v1
WHERE entity_name='policy_qualification' AND status='open'
ON CONFLICT DO NOTHING;
INSERT INTO s1_audit.source SELECT case_key,due_at FROM mdm_steward.policy_cases_v1
WHERE case_key IN (SELECT case_key FROM s1_claimed.cases) ON CONFLICT DO NOTHING;
SELECT pgreact_mdm.sync_intent_case_identities();
SET SESSION AUTHORIZATION mdm_s1_runner;
SELECT pgreact_api.author_deadline_rule('s1-claimed-work',
    'pgreact_mdm.intent_deployer_policy_cases_v1'::regclass,'case_key','due_at','COMMAND',
    'pgreact_mdm.submit_escalation_intent(pgreact.activation_context,pgreact_mdm.intent_deployer_policy_cases_v1)');
RESET SESSION AUTHORIZATION;
SELECT pgreact_mdm.configure_intent_deployer('mdm_s1_runner');
SELECT pgreact_api.run();
CREATE FUNCTION s1_claimed.state() RETURNS jsonb LANGUAGE sql AS $state$
SELECT jsonb_build_object(
    'cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c),
    'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]') FROM mdm_steward.policy_receipts_v1 r),
    'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY work_ref),'[]') FROM pgreact_mdm.intent_requests r),
    'intent_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
    'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
    'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
    'holds',(SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY case_key),'[]') FROM pgreact_mdm.intent_holds h),
    'source',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.policy_qualification_source s),
    'technical_source',(SELECT jsonb_agg(to_jsonb(s) ORDER BY case_key) FROM s1_audit.source s))
$state$;
