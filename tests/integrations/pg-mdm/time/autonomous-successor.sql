\set ON_ERROR_STOP on
BEGIN;
-- Follow the producer's real resolution/publication lifecycle. These source
-- changes create recurrence; none is used to wake React after occurrence 2.
DELETE FROM public.policy_qualification_source WHERE id=1002;
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.refresh('policy_qualification','ALLOW');
RESET ROLE;
RESET SESSION AUTHORIZATION;
DO $assert$
BEGIN
    IF NOT EXISTS (SELECT FROM mdm_steward.policy_cases_v1 c
        JOIN s1_auto.issue i ON i.original_key=c.case_key
        WHERE c.status='resolved' AND c.occurrence=1) THEN
        RAISE EXCEPTION 'MDM did not resolve occurrence 1';
    END IF;
END
$assert$;
INSERT INTO public.policy_qualification_source VALUES
    (1002,'Autonomous One','auto-pair@example.test',statement_timestamp());
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.refresh('policy_qualification','ALLOW');
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT c.case_key,c.action_revision FROM mdm_steward.policy_cases_v1 c
JOIN s1_auto.issue i ON i.issue_key=c.issue_key
WHERE c.entity_name='policy_qualification' AND c.status='open' AND c.occurrence=2
\gset
-- Due time and current level remain MDM human controls. No React enrollment,
-- refresh, explicit cycle or direct escalation call is allowed here.
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm_steward.set_case_controls(:case_key,NULL,
    statement_timestamp() - interval '1 hour',1,false,:action_revision,
    'Autonomous recurrence: authorized successor next-level setup');
RESET ROLE;
RESET SESSION AUTHORIZATION;
CREATE TABLE s1_auto.before_successor AS SELECT s1_auto.state() AS vector;
COMMIT;
