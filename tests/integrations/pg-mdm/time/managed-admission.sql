\set ON_ERROR_STOP on
SET TIME ZONE 'UTC';
CREATE SCHEMA cycle_bound;
CREATE TABLE cycle_bound.source(id bigint PRIMARY KEY, deadline timestamptz NOT NULL);
INSERT INTO cycle_bound.source VALUES
    (1,'2000-01-01 00:00:00+00'), (2,'2000-01-02 00:00:00+00'),
    (3,'2100-01-01 00:00:00+00');
CREATE TABLE cycle_bound.actions(LIKE cycle_bound.source INCLUDING ALL);
CREATE VIEW cycle_bound.candidate AS SELECT * FROM cycle_bound.source;
CREATE FUNCTION cycle_bound.deliver(
    context pgreact.activation_context, candidate cycle_bound.candidate
) RETURNS void LANGUAGE SQL AS $callback$
    INSERT INTO cycle_bound.actions VALUES (($2).id,($2).deadline)
$callback$;
SELECT pgreact_api.author_deadline_rule(
    'cycle-bound','cycle_bound.candidate'::regclass,'id','deadline','COMMAND',
    'cycle_bound.deliver(pgreact.activation_context,cycle_bound.candidate)');

CREATE FUNCTION cycle_bound.state() RETURNS jsonb LANGUAGE SQL AS $state$
    SELECT jsonb_build_object(
        'actions',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM cycle_bound.actions a),
        'work',(SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id',(a.new_bindings->>'id')::bigint,'state',a.state,
            'claimable',w.claimable) ORDER BY (a.new_bindings->>'id')::bigint),'[]')
            FROM pgreact_internal.agenda a JOIN pgreact.work w ON w.work_id=a.episode_id::text
            WHERE w.name='cycle-bound'),
        'attempts',(SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'id',(a.new_bindings->>'id')::bigint,'attempt_no',e.attempt_no,
            'status',e.status,'error_code',e.error_code) ORDER BY (a.new_bindings->>'id')::bigint),'[]')
            FROM pgreact_internal.agenda a JOIN pgreact.attempts e USING(episode_id)
            WHERE e.name='cycle-bound'))
$state$;
CREATE TABLE cycle_bound.evidence(cycle integer PRIMARY KEY, result jsonb, state jsonb);
DO $cycles$
DECLARE result jsonb; actual jsonb; expected jsonb;
BEGIN
    IF current_setting('pg_react.batch_size') <> '1' THEN
        RAISE EXCEPTION 'qualification requires batch_size=1';
    END IF;
    result := pgreact_api.managed_cycle();
    actual := cycle_bound.state();
    expected := '{"actions":[{"id":1,"deadline":"2000-01-01T00:00:00+00:00"}],
        "work":[{"id":1,"state":"COMPLETED","claimable":false},
                {"id":2,"state":"PENDING","claimable":true}],
        "attempts":[{"id":1,"attempt_no":1,"status":"COMPLETED","error_code":null}]}';
    IF actual IS DISTINCT FROM expected
       OR (result-'run'-'runtime_state') IS DISTINCT FROM
          '{"state":"ready","processed_jobs":1,"pending_jobs":1}'::jsonb THEN
        RAISE EXCEPTION 'first managed cycle exceeded admission bound or lost pending work: % / %', result,actual;
    END IF;
    INSERT INTO cycle_bound.evidence VALUES (1,result,actual);
    result := pgreact_api.managed_cycle();
    actual := cycle_bound.state();
    expected := '{"actions":[{"id":1,"deadline":"2000-01-01T00:00:00+00:00"},
                             {"id":2,"deadline":"2000-01-02T00:00:00+00:00"}],
        "work":[{"id":1,"state":"COMPLETED","claimable":false},
                {"id":2,"state":"COMPLETED","claimable":false}],
        "attempts":[{"id":1,"attempt_no":1,"status":"COMPLETED","error_code":null},
                    {"id":2,"attempt_no":1,"status":"COMPLETED","error_code":null}]}';
    IF actual IS DISTINCT FROM expected
       OR (result-'run'-'runtime_state') IS DISTINCT FROM
          '{"state":"ready","processed_jobs":1,"pending_jobs":0}'::jsonb THEN
        RAISE EXCEPTION 'second managed cycle did not drain the distinct remaining case: % / %', result,actual;
    END IF;
    INSERT INTO cycle_bound.evidence VALUES (2,result,actual);
    result := pgreact_api.managed_cycle();
    IF cycle_bound.state() IS DISTINCT FROM expected
       OR (result-'run'-'runtime_state') IS DISTINCT FROM
          '{"state":"ready","processed_jobs":0,"pending_jobs":0}'::jsonb
       OR (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM cycle_bound.source s)
          IS DISTINCT FROM '[{"id":1,"deadline":"2000-01-01T00:00:00+00:00"},
                            {"id":2,"deadline":"2000-01-02T00:00:00+00:00"},
                            {"id":3,"deadline":"2100-01-01T00:00:00+00:00"}]'::jsonb THEN
        RAISE EXCEPTION 'later managed cycle replayed work, admitted a future case, or changed sources: %',result;
    END IF;
    INSERT INTO cycle_bound.evidence VALUES (3,result,expected);
END
$cycles$;
SELECT 'managed cycle admission vectors passed';
