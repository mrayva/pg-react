\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
-- These are real source records and publications, using MDM's own recurrence
-- lifecycle. The selector is fixed by issue_key, never by the successor key.
SELECT pgreact_api.pause_rule(rule_name) FROM pgreact.rules WHERE state='ACTIVE';
CREATE SCHEMA s1_auto;
CREATE ROLE s1_inspector LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT s1_reader TO s1_inspector;
GRANT USAGE ON SCHEMA pgreact_mdm TO s1_reader;
INSERT INTO public.policy_qualification_source VALUES
    (1001, 'Autonomous One', 'auto-one@example.test', statement_timestamp()),
    (1002, 'Autonomous One', 'auto-pair@example.test', statement_timestamp()),
    (1003, 'Autonomous Two', 'auto-two@example.test', statement_timestamp()),
    (1004, 'Autonomous Two', 'auto-pair@example.test', statement_timestamp());
CREATE TABLE s1_auto.prior_cases AS SELECT case_key FROM mdm_steward.policy_cases_v1;
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.refresh('policy_qualification', 'ALLOW');
RESET ROLE;
RESET SESSION AUTHORIZATION;
CREATE TABLE s1_auto.issue AS
SELECT issue_key, case_key AS original_key FROM mdm_steward.policy_cases_v1
WHERE entity_name='policy_qualification' AND status='open' AND occurrence=1
  AND case_key NOT IN (SELECT case_key FROM s1_auto.prior_cases);
ALTER TABLE s1_auto.issue ADD PRIMARY KEY (issue_key);
DO $assert$
BEGIN
    IF (SELECT count(*) FROM s1_auto.issue) <> 1 THEN
        RAISE EXCEPTION 'expected one new MDM issue: %',
            (SELECT jsonb_agg(to_jsonb(c)) FROM mdm_steward.policy_cases_v1 c);
    END IF;
END
$assert$;
SELECT c.case_key, c.action_revision FROM mdm_steward.policy_cases_v1 c
JOIN s1_auto.issue i ON i.original_key=c.case_key
\gset
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm_steward.set_case_controls(:case_key, NULL,
    statement_timestamp() - interval '1 hour', 1, false, :action_revision,
    'Autonomous recurrence: authorized initial next-level setup');
RESET ROLE;
RESET SESSION AUTHORIZATION;
-- Initial deployment enrolls occurrence 1. There is no sync after recurrence.
SELECT pgreact_mdm.sync_intent_case_identities();
GRANT USAGE, CREATE ON SCHEMA s1_auto TO mdm_s1_runner;
GRANT SELECT ON s1_auto.issue TO mdm_s1_runner;
SET SESSION AUTHORIZATION mdm_s1_runner;
CREATE VIEW s1_auto.candidate AS
SELECT p.case_key, p.due_at AS deadline
FROM pgreact_mdm.intent_deployer_policy_cases_v1 p
JOIN mdm_steward.policy_cases_v1 c ON c.case_key=p.case_key AND c.entity_name=p.entity_name
JOIN s1_auto.issue i ON i.issue_key=c.issue_key
WHERE p.entity_name='policy_qualification' AND p.status='open'
  AND p.due_at IS NOT NULL AND p.escalation_level=1;
CREATE FUNCTION s1_auto.deliver(
    context pgreact.activation_context, candidate s1_auto.candidate
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $callback$
DECLARE current_case pgreact_mdm.intent_deployer_policy_cases_v1;
BEGIN
    SELECT p.* INTO STRICT current_case
    FROM pgreact_mdm.intent_deployer_policy_cases_v1 p WHERE p.case_key=($2).case_key;
    PERFORM pgreact_mdm.submit_escalation_intent($1,current_case);
END
$callback$;
REVOKE ALL ON FUNCTION s1_auto.deliver(pgreact.activation_context,s1_auto.candidate) FROM PUBLIC;
SELECT pgreact_api.author_deadline_rule('s1-autonomous',
    's1_auto.candidate'::regclass,'case_key','deadline','COMMAND',
    's1_auto.deliver(pgreact.activation_context,s1_auto.candidate)');
RESET SESSION AUTHORIZATION;
REVOKE CREATE ON SCHEMA s1_auto FROM mdm_s1_runner;
CREATE FUNCTION s1_auto.state() RETURNS jsonb LANGUAGE sql AS $state$
SELECT jsonb_build_object(
    'cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c),
    'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]') FROM mdm_steward.policy_receipts_v1 r),
    'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY work_ref),'[]') FROM pgreact_mdm.intent_requests r),
    'intent_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),
    'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),
    'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a),
    'source',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.policy_qualification_source s),
    'selector',(SELECT jsonb_agg(to_jsonb(i)) FROM s1_auto.issue i),
    'identities',(SELECT jsonb_agg(to_jsonb(i) ORDER BY case_identity) FROM pgreact_mdm.intent_case_identities i),
    'identity_sequence',(SELECT jsonb_build_object('last_value',last_value,'is_called',is_called)
                         FROM pgreact_mdm.intent_case_identities_case_identity_seq))
$state$;
