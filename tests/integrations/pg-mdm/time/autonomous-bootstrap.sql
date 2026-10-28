\set ON_ERROR_STOP on
CREATE ROLE mdm_helper_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE mdm_legacy_administrator NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE mdm_administrator NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE mdm_legacy_login LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT mdm_legacy_administrator TO mdm_legacy_login WITH SET TRUE, INHERIT FALSE;
CREATE DATABASE s1_idle;
\connect s1_idle postgres
CREATE EXTENSION pg_trickle;
CREATE EXTENSION pg_mdm;
CREATE EXTENSION pg_react;
\set helper_owner mdm_helper_owner
\ir /sql/configure_helper.sql
GRANT USAGE ON SCHEMA mdm,mdm_admin,mdm_steward,public TO mdm_legacy_administrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA mdm,mdm_admin,mdm_steward TO mdm_legacy_administrator;
GRANT SELECT ON mdm_steward.policy_cases_v1 TO mdm_legacy_administrator;
CREATE TABLE public.policy_qualification_source (
    id bigint PRIMARY KEY, display_name text NOT NULL,
    email_address text, updated_at timestamptz NOT NULL);
GRANT SELECT,MAINTAIN ON public.policy_qualification_source TO mdm_legacy_administrator;
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.create(mdm.entity(
    name=>'policy_qualification',
    sources=>ARRAY[mdm.source(name=>'policy',
        relation=>'public.policy_qualification_source'::regclass,
        source_id=>ARRAY['id'],mode=>'tracked',
        fields=>jsonb_build_object('name','display_name','email','email_address'),
        row_changed_at=>'updated_at')],
    fields=>ARRAY[mdm.field(name=>'name',type=>'text',cleaner=>'company_name'),
        mdm.field(name=>'email',type=>'text',cleaner=>'email')],
    matches=>ARRAY[mdm.match(name=>'same_name',fields=>ARRAY['name'],comparison=>'exact',
        strength=>'identity',evidence_group=>'name',
        candidate=>jsonb_build_object('kind','exact','field','name')),
        mdm.match(name=>'same_email',fields=>ARRAY['email'],comparison=>'exact',
        strength=>'strong',evidence_group=>'email',
        candidate=>jsonb_build_object('kind','exact','field','email'))],
    golden_values=>ARRAY[mdm.golden_value(field=>'name',policy=>'prefer_source',sources=>ARRAY['policy'])],
    execution_role=>'mdm_legacy_administrator'),NULL,'Autonomous recurrence fixture');
RESET ROLE;
RESET SESSION AUTHORIZATION;
INSERT INTO public.policy_qualification_source VALUES
    (1,'Seed One','seed-one@example.test',statement_timestamp()),
    (2,'Seed One','seed-pair@example.test',statement_timestamp()),
    (3,'Seed Two','seed-two@example.test',statement_timestamp()),
    (4,'Seed Two','seed-pair@example.test',statement_timestamp());
SET SESSION AUTHORIZATION mdm_legacy_login;
SET ROLE mdm_legacy_administrator;
SELECT mdm.refresh('policy_qualification','ALLOW');
SELECT case_key,action_revision FROM mdm_steward.policy_cases_v1
WHERE entity_name='policy_qualification' AND status='open'
\gset
SELECT mdm_steward.set_case_controls(:case_key,NULL,
    statement_timestamp()-interval '1 hour',1,false,:action_revision,'Initial deployment seed');
RESET ROLE;
RESET SESSION AUTHORIZATION;
