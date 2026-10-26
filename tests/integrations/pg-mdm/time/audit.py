#!/usr/bin/env python3
"""Run the S1 entry audit in one disposable joint-stack container."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid


def main():
    image, output = sys.argv[1:3]
    maintenance = sys.argv[3:] == ["--maintenance"]
    compatibility_only = sys.argv[3:] == ["--compatibility"]
    outage_mode = sys.argv[3:] == ["--outage"]
    multi_outage = sys.argv[3:] == ["--multi-outage"]
    pending_recovery = sys.argv[3:] == ["--pending-recovery"]
    if sys.argv[3:] and not (maintenance or compatibility_only or outage_mode or multi_outage or pending_recovery):
        raise ValueError("only --maintenance, --compatibility, --outage, --multi-outage or --pending-recovery is supported after IMAGE OUTPUT")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[4]
    container = "pgreact-s1-" + uuid.uuid4().hex[:12]
    observations = {"image": image, "checks": [], "entry_decision": "INCOMPLETE", "release_qualified": False}
    profile_path = root / "plans/v0.49-qualification-profile.json"
    profile = json.loads(profile_path.read_text())
    observations["qualification_profile"] = profile
    observations["qualification_profile_sha256"] = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    observations["tested_max_claims_per_cycle"] = profile["focused_safety_max_claims_per_cycle"]
    observations["qualification_scope"] = "Focused safety/recovery at one claim per cycle; release workload capacity is not qualified."
    created = False

    def command(*args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise RuntimeError(" ".join(args) + "\n" + result.stdout + result.stderr)
        return result.stdout

    def sql(query, database="s1_idle", port=5432):
        return command("docker", "exec", container, "psql", "-XAtq", "-U",
                       "postgres", "-p", str(port), "-d", database,
                       "-v", "ON_ERROR_STOP=1", "-c", query).strip()

    def timestamp(value):
        try:
            return datetime.datetime.fromisoformat(value)
        except ValueError:
            layout = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in value else "%Y-%m-%dT%H:%M:%S%z"
            return datetime.datetime.strptime(value, layout)

    def fixture(name, file, database="foundation", variables=()):
        started = time.monotonic()
        try:
            result = command("docker", "exec", container, "psql", "-XAtq", "-U",
                             "postgres", "-d", database, "-v", "ON_ERROR_STOP=1", *variables, "-f", file)
        except RuntimeError as error:
            (output / (name + ".log")).write_text(str(error))
            observations["checks"].append({"name": name, "result": "failed"})
            raise
        (output / (name + ".log")).write_text(result)
        observations["checks"].append({"name": name, "result": "passed",
                                       "seconds": time.monotonic() - started})
        print("PASS: " + name, flush=True)

    def cases():
        return json.loads(sql("SELECT jsonb_agg(to_jsonb(c) ORDER BY c.case_key) "
                              "FROM mdm_steward.policy_cases_v1 c"))

    def qualify_recovery(state_query, pending=False):
        before = json.loads(sql(state_query))
        source_oid = int(sql("SELECT oid FROM pg_database WHERE datname=current_database()"))
        assert sql(
            "SELECT r.state='active' AND r.database_oid=" + str(source_oid) +
            " FROM pgreact_mdm.policy_intent_bindings b "
            "JOIN mdm_internal.policy_binding_runtime r USING(binding_id) "
            "WHERE b.policy_revision='s1-idle-feasibility' AND b.enabled") == "t"
        sql("ALTER DATABASE s1_idle ALLOW_CONNECTIONS false", "postgres")
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='s1_idle'", "postgres")
        try:
            command("docker", "exec", container, "createdb", "-U", "postgres",
                    "--template=s1_idle", "s1_clone")
        finally:
            sql("ALTER DATABASE s1_idle ALLOW_CONNECTIONS true", "postgres")
        assert int(sql("SELECT oid FROM pg_database WHERE datname=current_database()",
                       "s1_clone")) != source_oid
        assert json.loads(sql(state_query, "s1_clone")) == before
        fixture("active-template-clone-guard",
                "/work/tests/integrations/pg-mdm/time/recovery.sql", "s1_clone",
                ("-v", "pending=" + str(pending).lower()))
        assert json.loads(sql(state_query, "s1_clone")) == before
        observations["active_template_clone"] = {
            "source_database_oid": source_oid,
            "clone_database_oid": int(sql(
                "SELECT oid FROM pg_database WHERE datname=current_database()", "s1_clone")),
            "complete_state": before, "unchanged_before_activation": True,
        }
        if pending:
            sql("SELECT pgtrickle.recover_capture_instance()", "s1_clone")
            fixture("template-clone-pending-reconcile",
                    "/work/tests/integrations/pg-mdm/time/recovery.sql", "s1_clone",
                    ("-v", "pending=true", "-v", "activate=true"))
            assert json.loads(sql(state_query, "s1_clone")) == before
            # Capture adoption deliberately suspends copied streams until the operator resumes them.
            sql("SELECT pgtrickle.resume_stream_table(format('%I.%I',pgt_schema,pgt_name)) "
                "FROM pgtrickle.pgt_stream_tables WHERE status='SUSPENDED' ORDER BY pgt_id", "s1_clone")
            drain_restored_pending(state_query, before, "s1_clone")
            assert json.loads(sql(state_query)) == before, "clone recovery changed the source"

        # Pause through the entity authority before taking a coherent backup.
        binding = json.loads(sql(
            "SELECT jsonb_build_object('id',b.binding_id,'version',r.runtime_version) "
            "FROM pgreact_mdm.policy_intent_bindings b "
            "JOIN mdm_internal.policy_binding_runtime r USING(binding_id) "
            "WHERE b.policy_revision='s1-idle-feasibility' AND b.enabled"))
        sql("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT pgreact_mdm.pause_intent_binding('" + str(uuid.UUID(binding["id"])) +
            "'::uuid," + str(int(binding["version"])) + ")")
        assert json.loads(sql(state_query)) == before
        started = time.monotonic()
        wal_before = sql("SELECT pg_current_wal_insert_lsn()")
        resource_before = json.loads(command(
            "docker", "stats", "--no-stream", "--format", "{{json .}}", container))
        backup_started = time.monotonic()
        command("docker", "exec", "--user", "postgres", container,
                "pg_basebackup", "-U", "postgres", "-D", "/tmp/s1-recovered",
                "--wal-method=stream", "--checkpoint=fast")
        backup_seconds = time.monotonic() - backup_started
        restore_started = time.monotonic()
        command("docker", "exec", "--user", "postgres", container,
                "pg_ctl", "-D", "/tmp/s1-recovered", "-l", "/tmp/s1-recovered.log",
                "-o", "-p 55432 -k /var/run/postgresql -c pg_react.databases= -c pg_react.batch_size=1 "
                "-c pg_react.poll_interval_ms=1000 -c pg_trickle.enabled=off "
                "-c pg_trickle.cdc_mode=trigger -c pg_trickle.differential_max_change_ratio=1.0 "
                "-c default_transaction_isolation='read committed'", "-w", "start")
        startup_seconds = time.monotonic() - restore_started
        try:
            assert sql("SELECT current_setting('pg_react.databases')", port=55432) == ""
            assert int(sql("SELECT oid FROM pg_database WHERE datname=current_database()",
                           port=55432)) == source_oid
            assert json.loads(sql(state_query, port=55432)) == before
            for name, activate in (("physical-restore-guard", False),
                                   ("physical-restore-reconcile-replay", True)):
                result = command("docker", "exec", container, "psql", "-XAtq",
                                 "-U", "postgres", "-p", "55432", "-d", "s1_idle",
                                 "-v", "ON_ERROR_STOP=1", "-v", "activate=" + str(activate).lower(),
                                 "-v", "pending=" + str(pending).lower(),
                                 "-f", "/work/tests/integrations/pg-mdm/time/recovery.sql")
                (output / (name + ".log")).write_text(result)
                assert json.loads(sql(state_query, port=55432)) == before
                observations["checks"].append({"name": name, "result": "passed"})
                print("PASS: " + name, flush=True)
            observations["physical_recovery"] = {
                "same_database_oid": source_oid,
                "postmaster_start": sql("SELECT pg_postmaster_start_time()", port=55432),
                "seconds": time.monotonic() - started,
                "backup_seconds": backup_seconds,
                "restore_startup_seconds": startup_seconds,
                "source_database_bytes": int(sql("SELECT pg_database_size(current_database())")),
                "source_wal_bytes_during_recovery": int(sql(
                    "SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),'" + wal_before + "')::bigint")),
                "container_resources_before_backup": resource_before,
                "container_resources_with_restored_server": json.loads(command(
                    "docker", "stats", "--no-stream", "--format", "{{json .}}", container)),
                "measurement_scope": "Disposable recovery drill; shared-container resource samples, not workload capacity or process-memory limits.",
                "workers_disabled_on_startup": True,
                "complete_state": before,
                "unchanged_before_and_after_explicit_reconciliation": True,
            }
            if pending:
                drain_restored_pending(state_query, before, "s1_idle", 55432, automatic=True)
            observations["physical_recovery"]["seconds"] = time.monotonic() - started
            assert observations["physical_recovery"]["seconds"] <= profile["recovery_max_seconds"]
        finally:
            command("docker", "exec", "--user", "postgres", container,
                    "pg_ctl", "-D", "/tmp/s1-recovered", "-m", "fast", "-w", "stop")
        assert json.loads(sql(state_query)) == before, "recovery test changed the source effects"

    def drain_restored_pending(state_query, before, database, port=5432, automatic=False):
        pending_work = [w for w in before["work"] if w["state"] == "PENDING"]
        assert len(pending_work) == 1 and pending_work[0]["claimable"], pending_work
        pending_id = pending_work[0]["work_id"]
        context = json.loads(sql(
            "SELECT jsonb_build_object('case_key',(new_bindings->>'case_key')::bigint,"
            "'activation_id',activation_id,'rule_version_id',rule_version_id,"
            "'generation',activation_generation,'revision',activation_revision) "
            "FROM pgreact_internal.agenda WHERE episode_id=" + str(int(pending_id)), database, port))
        case = next(c for c in before["cases"] if c["case_key"] == context["case_key"])
        binding = json.loads(sql(
            "SELECT to_jsonb(b) FROM pgreact_mdm.policy_intent_bindings b "
            "WHERE b.enabled AND b.policy_revision='s1-idle-feasibility'", database, port))
        body = {
            "action": "ESCALATE", "arguments": {"level": 2}, "case_key": case["case_key"],
            "binding_id": binding["binding_id"], "policy_revision": "s1-idle-feasibility",
            "expected_policy_digest": binding["policy_digest"][2:],
            "expected_evidence_basis_digest": case["evidence_basis_digest"][2:],
            "evaluation_ref": "pgreact:" + context["activation_id"],
            "work_ref": "pgreact:" + context["rule_version_id"] + ":" + pending_id,
            **{"expected_" + name: case[name] for name in ("review_version", "definition_version",
                "publication_revision", "stewardship_epoch", "action_revision")}}
        key = sql("SELECT encode(pgreact_mdm.intent_request_key('{}'::uuid,"
            "'s1-idle-feasibility',{},{},{},'escalate_level_2',2),'hex')".format(
                binding["binding_id"], case["case_key"], context["generation"], case["action_revision"]), database, port)
        digest = sql("SELECT encode(pgreact_mdm.intent_request_digest('" +
            json.dumps(body).replace("'", "''") + "'::jsonb),'hex')", database, port)
        started = time.monotonic()
        if automatic:
            command("docker", "exec", "--user", "postgres", container,
                    "pg_ctl", "-D", "/tmp/s1-recovered", "-l", "/tmp/s1-recovered.log", "-m", "fast", "-w", "restart",
                    "-o", "-p 55432 -k /var/run/postgresql -c pg_react.databases=s1_idle "
                    "-c pg_react.worker_role=mdm_s1_runtime -c pg_react.batch_size=1 "
                    "-c pg_react.poll_interval_ms=1000 -c pg_trickle.enabled=off "
                    "-c pg_trickle.cdc_mode=trigger -c pg_trickle.differential_max_change_ratio=1.0 "
                    "-c default_transaction_isolation='read committed'")
            end = started + profile["recovery_max_seconds"]
            while time.monotonic() < end:
                if sql("SELECT state FROM pgreact.work WHERE work_id='" + pending_id + "'", database, port) == "COMPLETED":
                    # Read the worker after completion commits; a prior poll can still contain the copied PID.
                    status = json.loads(sql("SELECT pgreact_api.managed_status()", database, port))
                    observations["restored_pending_worker_status"] = status
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("restored background worker did not drain pending escalation")
            cycle = {"pid": status["process"]["pid"]}
            assert sql("SELECT usename FROM pg_stat_activity WHERE pid=" + str(int(cycle["pid"])), database, port) == "mdm_s1_runtime"
        else:
            cycle = json.loads(sql("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
                                   "SELECT jsonb_build_object('result',pgreact_api.managed_cycle(),"
                                   "'pid',pg_backend_pid())", database, port))
            result = cycle["result"]
            assert result["state"] == "ready" and result["processed_jobs"] == 1, result
        after = json.loads(sql(state_query, database, port))
        expected_cases = copy.deepcopy(before["cases"])
        expected_case = next(c for c in expected_cases if c["case_key"] == case["case_key"])
        expected_case["escalation_level"] = 2
        expected_case["action_revision"] += 1
        assert after["cases"] == expected_cases
        assert after["business"] == before["business"] and after["technical"] == before["technical"]
        new_receipts = [r for r in after["receipts"] if r not in before["receipts"]]
        assert len(new_receipts) == 1, new_receipts
        receipt = new_receipts[0]
        uuid.UUID(receipt["receipt_id"])
        expected_receipt = {
            "receipt_id": receipt["receipt_id"], "created_at": receipt["created_at"],
            "actor": "pgreact_mdm_worker", "selected_role_name": "pgreact_mdm_worker",
            "session_role_name": "mdm_s1_runtime", "action": "ESCALATE", "outcome": "APPLIED_CONTROL",
            "reason_code": "CONTROL_APPLIED", "case_key": case["case_key"],
            "binding_id": binding["binding_id"], "binding_version": binding["binding_version"],
            "action_revision": expected_case["action_revision"], "resulting_publication_revision": None,
            "request_body": body, "request_key": "\\x" + key, "request_digest": "\\x" + digest,
            "control": {k: expected_case[k] for k in
                        ("assigned_queue", "due_at", "escalation_level", "manual_assignment_protected")}}
        expected_receipt["control"]["due_at"] = sql(
            "SELECT due_at::text FROM mdm_steward.policy_cases_v1 WHERE case_key=" + str(case["case_key"]), database, port)
        assert new_receipts == [expected_receipt], {"expected": expected_receipt, "actual": new_receipts}
        assert after["receipts"] == before["receipts"] + [expected_receipt]
        new_requests = [r for r in after["requests"] if r not in before["requests"]]
        new_intent_attempts = [a for a in after["intent_attempts"] if a not in before["intent_attempts"]]
        assert len(new_requests) == len(new_intent_attempts) == 1
        request = new_requests[0]
        intent_attempt = new_intent_attempts[0]
        assert new_requests == [{
            "binding_id": binding["binding_id"], "request_key": "\\x" + key,
            "request_digest": "\\x" + digest, "request_body": body, "work_ref": body["work_ref"],
            "policy_revision": "s1-idle-feasibility", "case_key": case["case_key"],
            "lifecycle_generation": context["generation"], "action_revision": case["action_revision"],
            "consequence_identity": "escalate_level_2", "escalation_level": 2,
            "first_episode_id": int(pending_id), "created_at": request["created_at"]}], new_requests
        assert new_intent_attempts == [{
            "episode_id": int(pending_id), "attempt_no": 1,
            **{k: expected_receipt[k] for k in ("binding_id", "request_key", "request_digest",
                "request_body", "receipt_id", "outcome", "reason_code", "case_key", "action_revision",
                "control", "resulting_publication_revision")},
            "work_ref": body["work_ref"], "attempted_at": intent_attempt["attempted_at"]}], new_intent_attempts
        assert [r for r in after["requests"] if r not in new_requests] == before["requests"]
        assert [a for a in after["intent_attempts"] if a not in new_intent_attempts] == before["intent_attempts"]
        expected_work = copy.deepcopy(before["work"])
        restored_work = next(w for w in after["work"] if w["work_id"] == pending_id)
        expected_pending = next(w for w in expected_work if w["work_id"] == pending_id)
        expected_pending.update(state="COMPLETED", claimable=False, updated_at=restored_work["updated_at"])
        assert after["work"] == expected_work
        assert [a for a in after["attempts"] if str(a["episode_id"]) != pending_id] == before["attempts"]
        new_attempts = [a for a in after["attempts"] if str(a["episode_id"]) == pending_id]
        assert len(new_attempts) == 1, new_attempts
        attempt = new_attempts[0]
        assert new_attempts == [{
            "execution_id": attempt["execution_id"], "episode_id": int(pending_id), "attempt_no": 1,
            "worker_id": "pg-react-managed/" + database + "/" + str(cycle["pid"]),
            "status": "COMPLETED", "error_message": None, "error_code": None,
            "started_at": attempt["started_at"], "finished_at": attempt["finished_at"],
            "event_kind": "ACTIVATE", "name": "s1-future-idle"}], new_attempts
        assert timestamp(case["due_at"]) <= timestamp(attempt["started_at"]) <= timestamp(request["created_at"])
        # MDM receipts use statement_timestamp(); adapter audit rows use clock_timestamp().
        assert timestamp(case["due_at"]) <= timestamp(receipt["created_at"]) <= timestamp(attempt["finished_at"])
        assert timestamp(request["created_at"]) <= timestamp(intent_attempt["attempted_at"])
        assert timestamp(intent_attempt["attempted_at"]) <= timestamp(attempt["finished_at"])
        assert timestamp(attempt["finished_at"]) <= timestamp(restored_work["updated_at"])
        name = "pending-recovery-" + database + "-" + str(port)
        observations[name] = {"before": before, "expected_cases": expected_cases,
                              "expected_receipt": expected_receipt, "after": after,
                              "background_worker": automatic, "no_replay": False}
        if automatic and status["process"]["state"] == "error":
            observations["checks"].append({"name": name, "result": "failed", "actual": status})
            raise AssertionError("restored worker delivered pending work but evaluation is blocked: " + str(status))
        if automatic:
            first = timestamp(status["process"]["heartbeat_at"])
            end = started + profile["recovery_max_seconds"]
            while time.monotonic() < end:
                status = json.loads(sql("SELECT pgreact_api.managed_status()", database, port))
                observations["restored_later_worker_status"] = status
                if status["process"]["state"] == "ready" and timestamp(status["process"]["heartbeat_at"]) > first + datetime.timedelta(seconds=3):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("restored background worker did not complete later cycles: " + str(status))
        else:
            for _ in range(2):
                result = json.loads(sql("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
                                        "SELECT pgreact_api.managed_cycle()", database, port))
                assert result["state"] == "ready" and result["processed_jobs"] == 0, result
        assert json.loads(sql(state_query, database, port)) == after, "restored work replayed"
        elapsed = time.monotonic() - started
        assert elapsed <= profile["backlog_drain_max_seconds"]
        observations[name].update(drain_seconds=elapsed, no_replay=True)
        observations["checks"].append({"name": name, "result": "passed"})
        print("PASS: " + name, flush=True)

    def qualify_pending_recovery():
        sql("SELECT pgreact_api.pause_rule('s1-callback-failure')")
        end = time.monotonic() + 60
        while sql("SELECT bool_and(deadline <= clock_timestamp()) FROM s1_audit.source") != "t":
            assert time.monotonic() < end, "pending recovery setup did not reach both deadlines"
            time.sleep(0.2)
        # Fixture setup queues work; delivery below uses the restricted runtime login.
        sql("SELECT pgreact_api.run()")
        work = json.loads(sql("SELECT jsonb_agg(to_jsonb(w) ORDER BY work_id) "
                              "FROM pgreact.work w WHERE name='s1-future-idle'"))
        assert [{k: w[k] for k in ("state", "claimable")} for w in work] == [
            {"state": "PENDING", "claimable": True}, {"state": "PENDING", "claimable": True}], work
        result = json.loads(sql("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
                                "SELECT pgreact_api.managed_cycle()"))
        assert result["state"] == "ready" and result["processed_jobs"] == 1, result
        state_query = (
            "SELECT jsonb_build_object("
            "'cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c),"
            "'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r),"
            "'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),"
            "'intent_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),"
            "'work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY work_id) FROM pgreact.work w WHERE name='s1-future-idle'),"
            "'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a WHERE name='s1-future-idle'),"
            "'business',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.policy_qualification_source s),"
            "'technical',(SELECT jsonb_agg(to_jsonb(s) ORDER BY case_key) FROM s1_audit.source s))")
        before = json.loads(sql(state_query))
        observations["pending_setup"] = {"cycle": result, "state": before}
        assert sorted(w["state"] for w in before["work"]) == ["COMPLETED", "PENDING"], observations["pending_setup"]
        qualify_recovery(state_query, pending=True)
        observations["entry_decision"] = "FOCUSED_PENDING_RECOVERY_QUALIFIED"

    def qualify_two_case_outage(before, source, temporal_source):
        # This bounded fixture intentionally exercises two distinct, real MDM
        # occurrence identities. It is not a numerical S1 performance result.
        selected = {row["case_key"]: timestamp(row["deadline"]) for row in temporal_source}
        assert len(selected) == len(temporal_source) == 2, temporal_source
        assert len({row["deadline"] for row in temporal_source}) == 2, temporal_source
        assert all(t > datetime.datetime.now(datetime.timezone.utc)
                   for t in selected.values()), temporal_source
        original = {row["case_key"]: row for row in before}
        assert set(selected) <= set(original)
        expected = copy.deepcopy(before)
        for row in expected:
            if row["case_key"] in selected:
                assert row["status"] == "open" and not row["pending_stewardship"], row
                assert row["escalation_level"] == 1 and "ESCALATE" in row["permitted_actions"], row
                assert timestamp(row["due_at"]) == selected[row["case_key"]], row
                row["escalation_level"] = 2
                row["action_revision"] += 1

        state_query = (
            "SELECT jsonb_build_object("
            "'cases',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]') FROM mdm_steward.policy_cases_v1 c),"
            "'mdm_receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]') FROM mdm_steward.policy_receipts_v1 r),"
            "'intent_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),"
            "'intent_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),"
            "'rule_work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w WHERE name='s1-future-idle'),"
            "'rule_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') FROM pgreact.attempts a WHERE name='s1-future-idle'),"
            "'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),"
            "'technical',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s))"
        )
        before_state = json.loads(sql(state_query))
        assert before_state["cases"] == before and before_state["business"] == source
        assert before_state["technical"] == temporal_source
        assert not before_state["intent_requests"] and not before_state["intent_attempts"]
        assert not before_state["rule_work"] and not before_state["rule_attempts"]
        assert not [r for r in before_state["mdm_receipts"]
                    if r["request_body"].get("policy_revision") == "s1-idle-feasibility"]
        binding = json.loads(sql(
            "SELECT jsonb_build_object('binding_id',binding_id,'binding_version',binding_version,"
            "'policy_digest',encode(policy_digest,'hex')) FROM pgreact_mdm.policy_intent_bindings "
            "WHERE policy_revision='s1-idle-feasibility' AND enabled"))
        expected_controls = json.loads(sql(
            "SELECT jsonb_agg(jsonb_build_object('case_key',c.case_key,'control',"
            "jsonb_build_object('assigned_queue',c.assigned_queue,'due_at',c.due_at::text,"
            "'escalation_level',2,'manual_assignment_protected',c.manual_assignment_protected))"
            " ORDER BY c.case_key) FROM mdm_steward.policy_cases_v1 c "
            "WHERE c.case_key IN (" + ",".join(str(k) for k in sorted(selected)) + ")"))
        controls = {c["case_key"]: c["control"] for c in expected_controls}
        # The installed compatibility gate delegates to the bound-carrying
        # managed worker; inspect both deployed definitions and the public
        # claim implementation rather than assuming a direct GUC read.
        managed_definition = sql(
            "SELECT pg_get_functiondef("
            "'pgreact_internal.managed_cycle(integer)'::regprocedure)")
        worker_definition = sql(
            "SELECT pg_get_functiondef("
            "'pgreact_internal.managed_cycle_m44(integer)'::regprocedure)")
        claim_definition = sql(
            "SELECT pg_get_functiondef("
            "'pgreact.claim(text,integer,interval,text[])'::regprocedure)")
        normalized_managed = " ".join(managed_definition.split())
        normalized_worker = " ".join(worker_definition.split())
        normalized_claim = " ".join(claim_definition.split())
        assert "RETURN pgreact_internal.managed_cycle_m44(process_pid)" in normalized_managed, (
            "deployed compatibility gate no longer reaches the bounded managed worker")
        assert "batch_limit integer := current_setting('pg_react.batch_size')::integer" in normalized_worker, (
            "deployed managed worker does not read the configured batch claim limit")
        assert "claim_limit integer := least(batch_limit, 100)" in normalized_worker, (
            "deployed managed worker no longer derives the bounded claim size")
        assert "pgreact_api.claim(worker, claim_limit, interval '60 seconds')" in normalized_worker, (
            "deployed worker no longer forwards the derived claim limit")
        assert "processed := processed + 1" in normalized_worker, (
            "deployed managed worker no longer counts each claimed execution")
        assert "processed_jobs = processed_jobs + processed" in normalized_worker, (
            "deployed worker no longer persists cumulative processed counts")
        assert "count_claimed := count_claimed + 1" in normalized_claim, (
            "deployed public claim no longer increments its claim count")
        assert "EXIT WHEN count_claimed >= max_items" in normalized_claim, (
            "deployed public claim no longer stops at its requested numeric bound")
        assert "IF max_items NOT BETWEEN 1 AND claim_limit" in normalized_claim, (
            "deployed public claim no longer checks the operational bound")
        claim_limit = int(sql(
            "SELECT max_claims FROM pgreact_internal.operational_settings"))
        assert claim_limit >= 1, claim_limit
        observations["installed_cycle_claim_bound"] = {
            "managed_function": "pgreact_internal.managed_cycle(integer)",
            "managed_definition_sha256": hashlib.sha256(
                managed_definition.encode()).hexdigest(),
            "bound_carrying_function": "pgreact_internal.managed_cycle_m44(integer)",
            "bound_carrying_definition_sha256": hashlib.sha256(
                worker_definition.encode()).hexdigest(),
            "forwarded_claim_limit_expression": "least(batch_limit, 100)",
            "claim_function": "pgreact.claim(text,integer,interval,text[])",
            "claim_definition_sha256": hashlib.sha256(
                claim_definition.encode()).hexdigest(),
            "per_cycle_configured_claim_limit": 1,
            "public_operational_max_claims": claim_limit,
            "managed_to_claim_bound_verified": True,
        }
        original_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
        sql("ALTER SYSTEM SET pg_react.databases = 's1_idle'")
        sql("ALTER SYSTEM SET pg_react.worker_role = 'mdm_s1_runtime'")
        sql("ALTER SYSTEM SET pg_react.batch_size = '1'")
        command("docker", "stop", "-t", "10", container)
        stopped_at = datetime.datetime.now(datetime.timezone.utc)
        assert stopped_at < min(selected.values()), {
            "error": "PostgreSQL must stop before both deadlines",
            "stopped_at": stopped_at.isoformat(), "deadlines": temporal_source}
        assert command("docker", "inspect", "-f", "{{.State.Running}}", container).strip() == "false"
        while datetime.datetime.now(datetime.timezone.utc) <= max(selected.values()) + datetime.timedelta(seconds=2):
            time.sleep(0.2)
        restarted_at = datetime.datetime.now(datetime.timezone.utc)
        command("docker", "start", container)
        drain_start = time.monotonic()
        deadline = drain_start + 150
        received = []
        status = None
        receipt_progress = []
        last_keys = set()
        while time.monotonic() < deadline:
            ready = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres"],
                capture_output=True, timeout=15)
            if ready.returncode:
                time.sleep(0.2)
                continue
            received = json.loads(sql(
                "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY case_key,receipt_id),'[]') "
                "FROM mdm_steward.policy_receipts_v1 r "
                "WHERE r.request_body ->> 'policy_revision' = 's1-idle-feasibility'"))
            status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            keys = {row["case_key"] for row in received}
            assert len(received) <= 2 and len(keys) == len(received), {
                "unexpected duplicate or extra receipts": received}
            assert keys <= set(selected), {"unexpected case admitted": received}
            assert last_keys <= keys, {
                "applied receipts disappeared during backlog drain": received,
                "previous": sorted(last_keys)}
            receipt_progress.append({
                "elapsed_seconds": time.monotonic() - drain_start,
                "completed_case_keys": sorted(keys),
                "receipt_count": len(received),
                "worker_state": (status.get("process") or {}).get("state"),
                "pending_jobs": (status.get("process") or {}).get("pending_jobs"),
                "processed_jobs": (status.get("process") or {}).get("processed_jobs"),
                "heartbeat_at": (status.get("process") or {}).get("heartbeat_at"),
            })
            last_keys = keys
            if len(received) == 2:
                break
            time.sleep(0.2)
        assert len(received) == 2, {"error": "two-case managed backlog did not drain",
                                    "receipts": received, "status": status,
                                    "progress": receipt_progress}
        drain_elapsed_seconds = time.monotonic() - drain_start
        assert 0 < drain_elapsed_seconds <= 150, drain_elapsed_seconds
        assert receipt_progress and receipt_progress[-1]["receipt_count"] == 2
        assert all(sample["receipt_count"] in (0, 1, 2)
                   for sample in receipt_progress), receipt_progress
        # Two status polls cannot establish one worker cycle. A background
        # worker can complete several cycles, or update heartbeat twice within
        # one cycle, between observations regardless of elapsed time. Preserve
        # the measured cumulative-counter deltas without guessing a cycle
        # identity. The numeric per-call bound is proved separately by the
        # installed SQL call chain and the focused max_items=1 claim test.
        observed_counter_intervals = []
        latest_heartbeat = None
        latest_processed = None
        for sample in receipt_progress:
            hb = sample["heartbeat_at"]
            processed = sample["processed_jobs"]
            if hb is None or processed is None:
                continue
            parsed = timestamp(hb)
            if latest_heartbeat is not None and parsed > latest_heartbeat:
                elapsed = (parsed - latest_heartbeat).total_seconds()
                delta = processed - latest_processed
                assert delta >= 0, ("managed cumulative processed counter regressed", sample)
                observed_counter_intervals.append({
                    "from_heartbeat": latest_heartbeat.isoformat(),
                    "to_heartbeat": hb,
                    "elapsed_seconds": elapsed,
                    "processed_delta": delta,
                    "individual_cycle_attribution": False,
                })
            if latest_heartbeat is None or parsed > latest_heartbeat:
                latest_heartbeat = parsed
                latest_processed = processed
        observations["observed_counter_intervals"] = observed_counter_intervals
        new_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
        assert new_postmaster > original_postmaster
        assert new_postmaster > max(selected.values()) and new_postmaster >= restarted_at

        actual = json.loads(sql(state_query))
        assert actual["cases"] == expected, {"expected": expected, "actual": actual["cases"]}
        assert actual["business"] == source and actual["technical"] == temporal_source
        assert len(actual["intent_requests"]) == len(actual["intent_attempts"]) == 2, actual
        assert len(actual["rule_work"]) == len(actual["rule_attempts"]) == 2, actual
        assert all(w["state"] == "COMPLETED" and not w["claimable"]
                   for w in actual["rule_work"]), actual["rule_work"]
        assert all(a["status"] == "COMPLETED" and a["attempt_no"] == 1
                   and a["error_code"] is None
                   for a in actual["rule_attempts"]), actual["rule_attempts"]
        assert {r["case_key"] for r in received} == set(selected)
        assert {r["case_key"] for r in actual["intent_requests"]} == set(selected)
        assert len({r["request_key"] for r in received}) == 2
        assert len({r["receipt_id"] for r in received}) == 2
        requests = {r["case_key"]: r for r in actual["intent_requests"]}
        attempts = {a["case_key"]: a for a in actual["intent_attempts"]}
        assert set(attempts) == set(selected)
        work_ids = {int(w["work_id"]) for w in actual["rule_work"]}
        assert work_ids == {a["episode_id"] for a in actual["rule_attempts"]}
        for receipt in received:
            key = receipt["case_key"]
            prior = original[key]
            request = requests[key]
            attempt = attempts[key]
            body = receipt["request_body"]
            assert receipt["action"] == "ESCALATE"
            assert receipt["outcome"] == "APPLIED_CONTROL" and receipt["reason_code"] == "CONTROL_APPLIED"
            assert receipt["actor"] == "pgreact_mdm_worker"
            assert receipt["selected_role_name"] == "pgreact_mdm_worker"
            assert receipt["session_role_name"] == "mdm_s1_runtime"
            assert receipt["resulting_publication_revision"] is None
            assert receipt["binding_id"] == binding["binding_id"]
            assert receipt["binding_version"] == binding["binding_version"]
            assert receipt["action_revision"] == prior["action_revision"] + 1
            assert receipt["control"] == controls[key]
            assert timestamp(receipt["created_at"]) >= new_postmaster >= selected[key]
            assert body == request["request_body"] == attempt["request_body"]
            assert set(body) == {
                "action", "arguments", "case_key", "binding_id", "policy_revision",
                "expected_policy_digest", "expected_evidence_basis_digest",
                "evaluation_ref", "work_ref", "expected_review_version",
                "expected_definition_version", "expected_publication_revision",
                "expected_stewardship_epoch", "expected_action_revision"}
            assert body["action"] == "ESCALATE" and body["arguments"] == {"level": 2}
            assert body["case_key"] == key and body["binding_id"] == binding["binding_id"]
            assert body["policy_revision"] == "s1-idle-feasibility"
            assert body["expected_policy_digest"] == binding["policy_digest"]
            assert body["expected_evidence_basis_digest"] == prior["evidence_basis_digest"][2:]
            for field in ("review_version", "definition_version", "publication_revision",
                          "stewardship_epoch", "action_revision"):
                assert body["expected_" + field] == prior[field], (key, field, body)
            assert body["evaluation_ref"].startswith("pgreact:")
            assert body["work_ref"].startswith("pgreact:")
            assert request["request_key"] == attempt["request_key"] == receipt["request_key"]
            assert request["request_digest"] == attempt["request_digest"] == receipt["request_digest"]
            assert request["lifecycle_generation"] == 1 and request["consequence_identity"] == "escalate_level_2"
            assert attempt["receipt_id"] == receipt["receipt_id"]
            assert attempt["outcome"] == "APPLIED_CONTROL" and attempt["reason_code"] == "CONTROL_APPLIED"
            assert attempt["episode_id"] in work_ids
            assert attempt["attempt_no"] == 1

        inspections = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(i) ORDER BY i.case_key),'[]') "
            "FROM pgreact_mdm.delivery_inspection_v1 i "
            "WHERE i.policy_revision='s1-idle-feasibility' AND i.action='ESCALATE'"))
        assert {row["case_key"] for row in inspections} == set(selected), inspections
        cases_by_key = {row["case_key"]: row for row in actual["cases"]}
        receipts_by_key = {row["case_key"]: row for row in received}
        for inspection in inspections:
            key = inspection["case_key"]
            case_row = cases_by_key[key]
            receipt = receipts_by_key[key]
            attempt = attempts[key]
            assert {
                "policy_revision": inspection["policy_revision"],
                "policy_digest": inspection["policy_digest"],
                "binding_version": inspection["binding_version"],
                "action": inspection["action"],
                "delivery_outcome": inspection["delivery_outcome"],
                "delivery_reason_code": inspection["delivery_reason_code"],
                "mdm_receipt_id": inspection["mdm_receipt_id"],
                "mdm_outcome": inspection["mdm_outcome"],
                "mdm_reason_code": inspection["mdm_reason_code"],
                "current_case_status": inspection["current_case_status"],
                "current_due_at": timestamp(inspection["current_due_at"]).isoformat(),
                "requested_due_at": inspection["requested_due_at"],
                "requested_escalation_level": inspection["requested_escalation_level"],
                "applied_escalation_level": inspection["applied_escalation_level"],
                "current_escalation_level": inspection["current_escalation_level"],
                "current_manual_assignment_protected": inspection["current_manual_assignment_protected"],
                "current_pending_stewardship": inspection["current_pending_stewardship"],
            } == {
                "policy_revision": "s1-idle-feasibility",
                "policy_digest": binding["policy_digest"],
                "binding_version": binding["binding_version"],
                "action": "ESCALATE",
                "delivery_outcome": attempt["outcome"],
                "delivery_reason_code": attempt["reason_code"],
                "mdm_receipt_id": receipt["receipt_id"],
                "mdm_outcome": receipt["outcome"],
                "mdm_reason_code": receipt["reason_code"],
                "current_case_status": "open",
                "current_due_at": selected[key].isoformat(),
                "requested_due_at": None,
                "requested_escalation_level": 2,
                "applied_escalation_level": 2,
                "current_escalation_level": 2,
                "current_manual_assignment_protected": case_row["manual_assignment_protected"],
                "current_pending_stewardship": False,
            }, inspection

        settings = json.loads(sql(
            "SELECT jsonb_object_agg(name,setting) FROM pg_settings WHERE name IN "
            "('pg_react.poll_interval_ms','pg_react.batch_size','pg_react.max_pending_jobs')"))
        assert settings["pg_react.batch_size"] == "1", settings
        assert int(settings["pg_react.batch_size"]) <= claim_limit, (
            "managed batch exceeds operational max_claims", settings, claim_limit)
        first_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        heartbeat = timestamp(first_status["process"]["heartbeat_at"])
        limit = time.monotonic() + 35
        while time.monotonic() < limit:
            later = json.loads(sql("SELECT pgreact_api.managed_status()"))
            current = later.get("process") or {}
            if current.get("state") == "ready" and current.get("heartbeat_at") and (
                    timestamp(current["heartbeat_at"]) > heartbeat + datetime.timedelta(seconds=2)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker did not continue through later backlog-drain cycles")
        assert json.loads(sql(state_query)) == actual, "later managed cycles changed complete two-case vectors"
        command("docker", "restart", container)
        limit = time.monotonic() + 70
        final_status = None
        next_postmaster = None
        while time.monotonic() < limit:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True, timeout=15)
            if ready.returncode:
                time.sleep(0.2)
                continue
            next_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            final_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = final_status.get("process") or {}
            if (next_postmaster > new_postmaster and process.get("state") == "ready"
                    and process.get("heartbeat_at")
                    and timestamp(process["heartbeat_at"]) > timestamp(current["heartbeat_at"])):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({"error": "post-drain restart did not resume managed worker",
                                  "status": final_status})
        post_restart_first = timestamp(final_status["process"]["heartbeat_at"])
        limit = time.monotonic() + 35
        while time.monotonic() < limit:
            final_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = final_status.get("process") or {}
            if (process.get("state") == "ready" and process.get("heartbeat_at")
                    and timestamp(process["heartbeat_at"]) > post_restart_first
                    + datetime.timedelta(seconds=2)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("post-drain worker stopped advancing after cold restart")
        assert json.loads(sql(state_query)) == actual, "post-restart replay mutated two-case vectors"
        observations["multi_outage"] = {
            "stopped_at": stopped_at.isoformat(),
            "due_at": {str(k): t.isoformat() for k, t in sorted(selected.items())},
            "restart_requested_at": restarted_at.isoformat(),
            "new_postmaster": new_postmaster.isoformat(),
            "post_drain_restart": next_postmaster.isoformat(),
            "configured_limits": settings,
            "two_case_drain_seconds": drain_elapsed_seconds,
            "observed_receipt_progress": receipt_progress,
            "per_cycle_claim_bound": observations["installed_cycle_claim_bound"],
            "observed_counter_intervals": observed_counter_intervals,
            "two_receipts": received,
            "before": before_state,
            "after": actual,
            "exact": True,
            "no_replay_across_cycles_and_restart": True}
        observations["checks"].append({
            "name": "two-case-real-outage-drain-and-no-replay", "result": "passed"})
        observations["entry_decision"] = "FOCUSED_TWO_CASE_OUTAGE_QUALIFIED"
        print("PASS: two real overdue MDM cases drained after outage with batch_size=1 and no replay", flush=True)

    try:
        observations["react_revision"] = command("git", "-C", str(root), "rev-parse", "HEAD").strip()
        observations["source_sha256"] = {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(set(root.glob("src/*.rs")) | set(root.glob("integrations/pg-mdm/sql/*.sql")) |
                               set((root / "tests/integrations/pg-mdm/time").glob("*")) |
                               {root / "sql/pg_react--0.46.1.sql", root / "pg_react.control"})
            if path.is_file()
        }
        observations["image_id"] = command("docker", "image", "inspect", image,
                                           "--format", "{{.Id}}").strip()
        observations["image_labels"] = json.loads(command(
            "docker", "image", "inspect", image, "--format", "{{json .Config.Labels}}"))
        command("docker", "run", "--detach", "--name", container, "--network", "none",
                "--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--volume", str(root) + ":/work:ro",
                image, "postgres", "-c", "shared_preload_libraries=pg_trickle,pg_react",
                "-c", "pg_react.batch_size=" + str(profile["focused_safety_max_claims_per_cycle"]),
                "-c", "pg_react.poll_interval_ms=" + str(profile["poll_interval_ms"]),
                "-c", "pg_trickle.enabled=off", "-c", "pg_trickle.cdc_mode=trigger",
                "-c", "pg_trickle.differential_max_change_ratio=1.0",
                "-c", "default_transaction_isolation=read committed")
        created = True
        for _ in range(60):
            result = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                    capture_output=True)
            if result.returncode == 0 and "PostgreSQL init process complete" in command("docker", "logs", container):
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL readiness exceeded 60 seconds")
        command("docker", "exec", container, "createdb", "-U", "postgres", "s1_compatibility")
        sql("CREATE EXTENSION pg_trickle; CREATE EXTENSION pg_react", "s1_compatibility")
        observations["installed_profile"] = json.loads(sql(
            "SELECT jsonb_build_object('postgresql',version(),'extensions',"
            "(SELECT jsonb_object_agg(extname,extversion) FROM pg_extension),"
            "'settings',(SELECT jsonb_object_agg(name,setting) FROM pg_settings WHERE name IN "
            "('pg_trickle.enabled','pg_trickle.cdc_mode','pg_trickle.differential_max_change_ratio',"
            "'default_transaction_isolation','transaction_isolation','shared_preload_libraries')),"
            "'compatibility',pgreact_internal.pgtrickle_integration_status())", "s1_compatibility"))
        fixture("compatibility", "/work/tests/integrations/pg-mdm/time/compatibility.sql", "s1_compatibility")
        command("docker", "exec", container, "createdb", "-U", "postgres", "s1_compatibility_upgrade")
        sql("CREATE EXTENSION pg_trickle; CREATE EXTENSION pg_react VERSION '0.46.0'", "s1_compatibility_upgrade")
        fixture("populated-core-upgrade-rollback", "/work/tests/integrations/pg-mdm/time/upgrade-rollback.sql",
                "s1_compatibility_upgrade")
        observations["core_upgrade_rollback"] = json.loads(sql(
            "SELECT result FROM upgrade_rollback.evidence", "s1_compatibility_upgrade"))
        callable_query = (
            "SELECT jsonb_agg(jsonb_build_object('identity',p.oid::regprocedure::text,"
            "'owner',pg_get_userbyid(p.proowner),'acl',p.proacl::text,"
            "'definition',pg_get_functiondef(p.oid)) ORDER BY p.oid::regprocedure::text) "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname IN ('pgreact_internal','pgreact_api','pgreact') "
            "AND p.proname IN ('pgtrickle_capability_report','pgtrickle_integration_status',"
            "'require_pgtrickle_runtime','pgtrickle_health_findings','assert_m0_compatibility',"
            "'managed_cycle','doctor','health_check')")
        fresh = json.loads(sql(callable_query, "s1_compatibility"))
        upgraded = json.loads(sql(callable_query, "s1_compatibility_upgrade"))
        assert fresh == upgraded, "fresh/adjacent-upgrade compatibility definitions or privileges differ"
        assert json.loads(sql("SELECT pgreact_internal.pgtrickle_integration_status()",
            "s1_compatibility_upgrade")) == observations["installed_profile"]["compatibility"]
        observations["compatibility_callables"] = fresh
        observations["checks"].append({"name": "fresh-adjacent-upgrade-compatibility", "result": "passed"})
        print("PASS: fresh/adjacent-upgrade compatibility and callable privileges", flush=True)
        if compatibility_only:
            observations["entry_decision"] = "ADMISSION_ONLY"
            return
        command("docker", "exec", container, "createdb", "-U", "postgres", "s1_cycle_bound")
        sql("CREATE EXTENSION pg_trickle; CREATE EXTENSION pg_react", "s1_cycle_bound")
        fixture("managed-cycle-admission-bound",
                "/work/tests/integrations/pg-mdm/time/managed-admission.sql", "s1_cycle_bound")
        observations["managed_cycle_admission"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(e) ORDER BY cycle) FROM cycle_bound.evidence e", "s1_cycle_bound"))
        fixture("refresh-permission", "/work/tests/integrations/pg-mdm/time/refresh-permission.sql", "s1_compatibility")
        producer_archive = (observations["image_labels"] or {}).get("pg_trickle.source_archive_sha256")
        fixture("mdm-bootstrap", "/tests/e2e.sql", "postgres",
                ("-v", "producer_artifact_sha256=" + producer_archive) if producer_archive else ())
        fixture("mdm-policy-fixtures", "/tests/e2e_policy.sql")
        observations["mdm_entry_cases"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c", "foundation"))
        observations["mdm_entry_receipts"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r", "foundation"))
        observations["mdm_fixture_cases"] = observations["mdm_entry_cases"]
        fixture("idle-seed", "/work/tests/integrations/pg-mdm/time/idle-seed.sql")
        observations["mdm_entry_cases"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(c) ORDER BY case_key) FROM mdm_steward.policy_cases_v1 c", "foundation"))
        observations["fixture_sha256"] = command("docker", "exec", container, "sha256sum",
            "/tests/e2e.sql", "/tests/e2e_policy.sql", "/usr/lib/postgresql/18/lib/pg_react.so",
            "/usr/lib/postgresql/18/lib/pg_mdm.so", "/usr/lib/postgresql/18/lib/pg_trickle.so").splitlines()
        sql("ALTER DATABASE foundation ALLOW_CONNECTIONS false", "postgres")
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='foundation'", "postgres")
        try:
            command("docker", "exec", container, "createdb", "-U", "postgres",
                    "--template=foundation", "s1_idle")
            command("docker", "exec", container, "createdb", "-U", "postgres",
                    "--template=foundation", "s1_mdm_upgrade")
        finally:
            sql("ALTER DATABASE foundation ALLOW_CONNECTIONS true", "postgres")
        sql("CREATE EXTENSION pg_react VERSION '0.46.0'", "s1_mdm_upgrade")
        fixture("populated-mdm-upgrade-rollback", "/work/tests/integrations/pg-mdm/time/upgrade-rollback.sql",
                "s1_mdm_upgrade")
        observations["mdm_upgrade_rollback"] = json.loads(sql(
            "SELECT result FROM upgrade_rollback.evidence", "s1_mdm_upgrade"))
        command("docker", "exec", container, "dropdb", "-U", "postgres", "--force", "s1_mdm_upgrade")
        # Recover only the disposable clone's capture identity, before future-deadline setup.
        observations["clone_capture_recovery"] = sql("SELECT pgtrickle.recover_capture_instance()")
        assert cases() == observations["mdm_entry_cases"], "clone recovery changed MDM cases"
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                              "FROM mdm_steward.policy_receipts_v1 r")) == observations["mdm_entry_receipts"], "clone recovery changed MDM receipts"
        for database in ("foundation", "s1_idle"):
            version = "0.46.0" if maintenance and database == "foundation" else "0.46.1"
            sql("CREATE EXTENSION pg_react VERSION '{}'".format(version), database)
        entry = json.loads(sql("SELECT pgreact_api.managed_cycle()"))
        observations["runtime_entry"] = entry
        if entry["state"] == "blocked":
            for name in ("v0.47", "v0.48-codec"):
                fixture(name, "/work/tests/integrations/pg-mdm/" + name + ".sql", "postgres")
            fixture("runtime-gate", "/work/tests/integrations/pg-mdm/time/runtime-gate.sql", "s1_idle")
            observations["runtime_gate"] = json.loads(sql("SELECT vector FROM s1_runtime_gate.evidence"))
            before = cases()
            receipts_before = json.loads(sql(
                "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r"))
            source_before = json.loads(sql(
                "SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.policy_qualification_source s"))
            temporal_source = json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY case_key) FROM s1_runtime_gate.source s"))
            deadline = timestamp(temporal_source[0]["due_at"])
            for role in ("author", "operator", "worker", "reader", "advanced_reader"):
                sql("CREATE ROLE s1_gate_" + role + " LOGIN NOSUPERUSER NOBYPASSRLS")
            sql("SELECT pgreact_api.configure_roles('s1_gate_author','s1_gate_operator',"
                "'s1_gate_worker','s1_gate_reader','s1_gate_advanced_reader')")
            sql("ALTER SYSTEM SET pg_react.databases = 's1_idle'")
            sql("ALTER SYSTEM SET pg_react.worker_role = 's1_gate_worker'")
            command("docker", "restart", container)
            end = time.monotonic() + 30
            while time.monotonic() < end:
                ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"], capture_output=True)
                if not ready.returncode:
                    status = json.loads(sql("SELECT pgreact_api.managed_status()"))
                    process = status.get("process") or {}
                    if process.get("state") == "error" and timestamp(process["heartbeat_at"]) >= deadline:
                        break
                time.sleep(0.2)
            else:
                raise AssertionError("managed worker did not expose the gate after the idle deadline within 30 seconds")
            assert process["detail"] == "pg_trickle compatibility blocked: " + sql(
                "SELECT (vector #> '{cycle,compatibility}')::text FROM s1_runtime_gate.evidence"), status
            assert {key: value for key, value in status.items() if key != "process"} == {
                "contract_version": 5, "database": "s1_idle", "configured": True}, status
            assert {key: value for key, value in process.items() if key not in
                    ("pid", "started_at", "heartbeat_at", "detail")} == {
                "state": "error", "protocol": 2, "pending_jobs": 0, "processed_jobs": 0}, process
            assert sql("SELECT usename FROM pg_stat_activity WHERE pid=" + str(process["pid"])) == "s1_gate_worker"
            assert cases() == before
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                                  "FROM mdm_steward.policy_receipts_v1 r")) == receipts_before
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY id) "
                                  "FROM public.policy_qualification_source s")) == source_before
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY case_key) "
                                  "FROM s1_runtime_gate.source s")) == temporal_source
            public_state = json.loads(sql("SELECT jsonb_build_object("
                "'rules',(SELECT COALESCE(jsonb_agg(to_jsonb(r)),'[]') FROM pgreact.rules r),"
                "'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w)),'[]') FROM pgreact.work w),"
                "'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]') FROM pgreact.attempts a))"))
            assert public_state == {"rules": [], "work": [], "attempts": []}, public_state
            observations.update(entry_decision="STOP", managed_status=status, public_state=public_state,
                cases_before=before, cases_actual=cases(), receipts=receipts_before,
                business_source=source_before, temporal_source=temporal_source, idle_case_delivered=False,
                stop_reason="The MDM-qualified pg_trickle 0.108.3 producer is rejected by React's exact-0.108.0 admission guard; public temporal registration and managed dispatch are unavailable on this joint profile.",
                conditional_work_not_performed=["managed escalation implementation", "idle MDM delivery acceptance",
                    "bounded progression/recovery/concurrency acceptance", "numeric operating envelope"])
            observations["checks"].append({"name": "managed-runtime-compatibility-stop", "result": "confirmed"})
            print("STOP: public registration and actual managed worker reject the MDM-qualified producer; no control or receipt changes", flush=True)
            return
        sql("CREATE EXTENSION IF NOT EXISTS pg_trickle; CREATE EXTENSION IF NOT EXISTS pg_react", "postgres")
        for name in ("v0.47", "v0.47-typed", "v0.48-codec"):
            fixture(name, "/work/tests/integrations/pg-mdm/" + name + ".sql", "postgres")
        for name in ("v0.47-live-setup", "v0.47-live", "v0.48-codec", "v0.48-live", "v0.48-security"):
            fixture(name, "/work/tests/integrations/pg-mdm/" + name + ".sql")
        observations["foundation_receipts"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r", "foundation"))
        if maintenance:
            observations["maintenance"] = {}
            for database, upgrade in (("core_claim", False), ("core_upgrade", True), ("foundation", True)):
                if database != "foundation":
                    command("docker", "exec", container, "createdb", "-U", "postgres", database)
                    sql("CREATE EXTENSION pg_trickle; CREATE EXTENSION pg_react VERSION '" +
                        ("0.46.0" if upgrade else "0.46.1") + "'", database)
                else:
                    sql("SELECT pgreact_api.pause_rule(rule_name) FROM pgreact.rules WHERE state='ACTIVE'", database)
                    pause_commands = json.loads(sql(
                        "SELECT COALESCE(jsonb_agg(format('SET SESSION AUTHORIZATION %I; SET ROLE %I; "
                        "SELECT pgreact_mdm.pause_intent_binding(%L::uuid,%s)', "
                        "(SELECT login.rolname FROM pg_catalog.pg_roles login WHERE login.rolcanlogin "
                        "AND NOT login.rolsuper AND NOT login.rolbypassrls "
                        "AND pg_has_role(login.oid,b.entity_execution_role,'MEMBER') ORDER BY login.rolname LIMIT 1), "
                        "b.entity_execution_role,b.binding_id,r.runtime_version)), '[]') "
                        "FROM pgreact_mdm.policy_intent_bindings b JOIN pgreact_mdm.policy_intent_runtime r USING(binding_id) "
                        "WHERE b.enabled", database))
                    for pause in pause_commands:
                        sql(pause, database)
                fixture(database, "/work/tests/integrations/pg-mdm/time/maintenance.sql", database,
                        ("-v", "upgrade=" + str(upgrade).lower(), "-v", "direct=" + str(database != "foundation").lower()))
                observations["maintenance"][database] = json.loads(sql(
                    "SELECT jsonb_build_object('before',to_jsonb(b),'after',to_jsonb(a),'result',r.vector) "
                    "FROM claim_maintenance.before_upgrade b, claim_maintenance.after_upgrade a, "
                    "claim_maintenance.result r", database))
            assert observations["maintenance"]["core_claim"]["after"]["api"] == observations["maintenance"]["core_upgrade"]["after"]["api"], "fresh/upgrade public callable inventories differ"
        command("docker", "exec", "--user", "postgres", container, "sh",
                "/work/tests/integrations/pg-mdm/v0.48-admission.sh", "s1_missing_mdm", "current")
        observations["checks"].append({"name": "missing-mdm-admission", "result": "passed"})
        command("docker", "exec", container, "createdb", "-U", "postgres", "s1_boundary")
        sql("CREATE EXTENSION pg_trickle; CREATE EXTENSION pg_react", "s1_boundary")
        fixture("sample-boundaries", "/work/tests/integrations/pg-mdm/time/boundaries.sql", "s1_boundary")
        fixture("idle-setup", "/work/tests/integrations/pg-mdm/time/idle.sql", "s1_idle",
                ("-v", "multi=" + str(multi_outage or pending_recovery).lower(), "-v", "VERBOSITY=verbose"))
        if pending_recovery:
            qualify_pending_recovery()
            return
        observations["registered_s1_rules"] = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(jsonb_build_object('rule_name',r.rule_name,'rule_id',r.rule_id,"
            "'rule_version_id',v.rule_version_id,'match_name',v.match_name) ORDER BY r.rule_name),'[]') "
            "FROM pgreact_internal.rules r JOIN pgreact_internal.rule_versions v USING(rule_id) "
            "WHERE r.rule_name IN ('s1-callback-failure','s1-future-idle')"))
        observations["callback_failure_rule_ids"] = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY rule_id),'[]') "
            "FROM s1_audit.callback_failure_rules f"))
        assert [row["rule_name"] for row in observations["registered_s1_rules"]] == [
            "s1-callback-failure", "s1-future-idle"], observations["registered_s1_rules"]
        assert len(observations["callback_failure_rule_ids"]) == 1, observations["callback_failure_rule_ids"]
        assert observations["callback_failure_rule_ids"][0]["rule_id"] == next(
            row["rule_id"] for row in observations["registered_s1_rules"]
            if row["rule_name"] == "s1-callback-failure")
        observations["installed_extensions"] = json.loads(sql(
            "SELECT jsonb_agg(jsonb_build_object('name',extname,'version',extversion) ORDER BY extname) "
            "FROM pg_extension"))
        observations["server_version_num"] = int(sql("SELECT current_setting('server_version_num')"))
        observations["installed_functions"] = json.loads(sql(
            "SELECT jsonb_agg(jsonb_build_object('identity',p.oid::regprocedure::text,"
            "'owner',pg_get_userbyid(p.proowner),'security_definer',p.prosecdef,'acl',p.proacl::text,"
            "'result',pg_get_function_result(p.oid),"
            "'definition_sha256',encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')) "
            "ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname IN ('pgreact_api','pgreact_mdm','mdm_steward') AND p.prokind='f' "
            "AND p.proname IN ('author_deadline_rule','author_temporal_rule','validate_deadline_rule',"
            "'run','managed_status','managed_cycle','deadline_history','temporal_status','temporal_history',"
            "'submit_policy_intent','submit_escalation_intent','submit_intent_as_worker')"))
        before = cases()
        source = json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                                "FROM public.policy_qualification_source s"))
        temporal_source = json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                                         "FROM s1_audit.source s"))
        if multi_outage:
            qualify_two_case_outage(before, source, temporal_source)
            return
        assert len(temporal_source) == 1, temporal_source
        case_key = temporal_source[0]["case_key"]
        deadline = timestamp(temporal_source[0]["deadline"])
        expected = copy.deepcopy(before)
        for row in expected:
            if row["case_key"] == case_key:
                assert row["escalation_level"] == 1 and row["due_at"] == temporal_source[0]["deadline"]
                row["escalation_level"] = 2
                row["action_revision"] += 1
                expected_revision = row["action_revision"]
        expected_control = json.loads(sql(
            "SELECT jsonb_build_object('assigned_queue',c.assigned_queue,'due_at',c.due_at::text,"
            "'escalation_level',2,'manual_assignment_protected',c.manual_assignment_protected) "
            "FROM mdm_steward.policy_cases_v1 c WHERE c.case_key=" + str(case_key)))
        binding = json.loads(sql("SELECT jsonb_build_object('binding_id',binding_id,"
            "'binding_version',binding_version,'policy_digest',encode(policy_digest,'hex')) "
            "FROM pgreact_mdm.policy_intent_bindings "
            "WHERE policy_revision='s1-idle-feasibility' AND enabled"))
        uuid.UUID(binding["binding_id"])
        assert deadline > datetime.datetime.now(datetime.timezone.utc), temporal_source
        observations.update(cases_before=before, business_source=source,
                            temporal_source=temporal_source, cases_expected=expected)
        sql("ALTER SYSTEM SET pg_react.databases = 's1_idle'")
        sql("ALTER SYSTEM SET pg_react.worker_role = 'mdm_s1_runtime'")
        outage_before = None
        if outage_mode:
            # A genuine PostgreSQL outage starts before the *future* deadline,
            # remains down while that deadline passes, and ends only after it.
            # This is not a manual clock input, source update or worker tick.
            outage_postmaster_before = timestamp(sql("SELECT pg_postmaster_start_time()"))
            outage_before = json.loads(sql(
                "SELECT jsonb_build_object("
                "'cases',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]') FROM mdm_steward.policy_cases_v1 c),"
                "'receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]') FROM mdm_steward.policy_receipts_v1 r),"
                "'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') FROM pgreact_mdm.intent_requests r),"
                "'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') FROM pgreact_mdm.intent_attempts a),"
                "'work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') FROM pgreact.work w),"
                "'business',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.policy_qualification_source s),"
                "'technical',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') FROM s1_audit.source s))"))
            assert outage_before["cases"] == before
            assert outage_before["business"] == source
            assert outage_before["technical"] == temporal_source
            assert not [r for r in outage_before["receipts"]
                        if r["request_body"].get("policy_revision") == "s1-idle-feasibility"]
            command("docker", "stop", "-t", "10", container)
            stopped_at = datetime.datetime.now(datetime.timezone.utc)
            assert stopped_at < deadline, {
                "error": "PostgreSQL did not stop before the case was due",
                "stopped_at": stopped_at.isoformat(), "deadline": deadline.isoformat()}
            assert command("docker", "inspect", "-f", "{{.State.Running}}", container).strip() == "false"
            # Wait for the due boundary while PostgreSQL is completely stopped.
            # This sleep is a controlled outage stimulus, not the evidence of
            # delivery; the later real worker receipt and complete vectors are.
            while datetime.datetime.now(datetime.timezone.utc) <= deadline + datetime.timedelta(seconds=2):
                time.sleep(0.2)
            resumed_at = datetime.datetime.now(datetime.timezone.utc)
            assert resumed_at > deadline
            command("docker", "start", container)
            observations["outage_across_deadline"] = {
                "postmaster_before": outage_postmaster_before.isoformat(),
                "stopped_at": stopped_at.isoformat(),
                "deadline_at": deadline.isoformat(),
                "resume_requested_at": resumed_at.isoformat(),
                "complete_state_before": outage_before,
            }
        else:
            command("docker", "restart", container)
        end = time.monotonic() + 120
        receipts = []
        while time.monotonic() < end:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if ready.returncode:
                time.sleep(0.2)
                continue
            receipts = json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.receipt_id), '[]') "
                "FROM mdm_steward.policy_receipts_v1 r WHERE request_body->>'policy_revision'='s1-idle-feasibility'"))
            status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            detail = (status.get("process") or {}).get("detail") or ""
            if receipts or (detail.startswith("42702:") and '"rule_version_id" is ambiguous' in detail):
                break
            if detail.startswith("permission denied: must be owner of stream table ") and \
                    datetime.datetime.now(datetime.timezone.utc) >= deadline:
                break
            failed = sql("SELECT EXISTS (SELECT 1 FROM pgreact.attempts "
                         "WHERE name='s1-future-idle' AND status='FAILED' "
                         "AND error_message <> 'injected registered S1 callback failure')")
            if failed == "t" and datetime.datetime.now(datetime.timezone.utc) >= deadline:
                break
            time.sleep(0.2)
        observations["runtime_settings"] = json.loads(sql(
            "SELECT jsonb_object_agg(name,setting) FROM pg_settings WHERE name IN "
            "('pg_react.databases','pg_react.worker_role','pg_react.poll_interval_ms',"
            "'pg_react.batch_size','pg_react.max_pending_jobs','max_worker_processes')"))
        observations["managed_status"] = json.loads(sql("SELECT pgreact_api.managed_status()"))
        observations["work"] = json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') "
                                              "FROM pgreact.work w WHERE name='s1-future-idle'"))
        observations["attempts"] = json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') "
                                                  "FROM pgreact.attempts a WHERE name='s1-future-idle'"))
        if not receipts and ((observations["managed_status"].get("process") or {}).get("detail") or "").startswith("42702:"):
            query = "SELECT * FROM pgreact.claim('s1-independent-diagnostic',32,interval '60 seconds',NULL::text[])"
            failure = subprocess.run(["docker", "exec", container, "psql", "-XAtq", "-U", "postgres",
                "-d", "s1_idle", "-v", "VERBOSITY=verbose", "-c", query], capture_output=True, text=True)
            observations["generic_claim_failure"] = {"query": query, "exit": failure.returncode,
                                                    "stdout": failure.stdout, "stderr": failure.stderr}
            assert failure.returncode != 0 and "42702" in failure.stderr, failure.stderr
            assert 'column reference "rule_version_id" is ambiguous' in failure.stderr, failure.stderr
            assert "pgreact.claim(text,integer,interval,text[])" in failure.stderr, failure.stderr
            observations["generic_claim_definition"] = sql(
                "SELECT pg_get_functiondef('pgreact.claim(text,integer,interval,text[])'::regprocedure)")
            observations["cases_actual"] = cases()
            assert observations["cases_actual"] == before, "generic STOP changed the complete MDM case population"
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                                  "FROM public.policy_qualification_source s")) == source
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                                  "FROM s1_audit.source s")) == temporal_source
            observations["receipts_actual"] = json.loads(sql(
                "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r"))
            assert observations["receipts_actual"] == observations["mdm_entry_receipts"], "generic STOP changed retained public receipts"
            observations["entry_decision"] = "STOP"
            observations["stop_reason"] = "The installed generic managed claim operation fails before dispatch; working idle-time support is unavailable on this exact artifact."
            observations["conditional_work_not_performed"] = ["1000-case due/churn measurements", "numeric envelope/sign-off",
                "downstream S2/S3 implementation and qualification"]
            observations["checks"].append({"name": "generic-claim-unavailability", "result": "confirmed",
                                            "sqlstate": "42702"})
            print("STOP: independently confirmed generic managed claim defect 42702; re-estimation required", flush=True)
            return
        if not receipts:
            observations["cases_actual"] = cases()
            observations["receipts_actual"] = json.loads(sql(
                "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) FROM mdm_steward.policy_receipts_v1 r"))
            assert observations["cases_actual"] == before, "blocked worker changed MDM cases"
            assert observations["receipts_actual"] == observations["mdm_entry_receipts"], "blocked worker changed MDM receipts"
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                                  "FROM public.policy_qualification_source s")) == source
            assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                                  "FROM s1_audit.source s")) == temporal_source
            observations["blocked_populations_unchanged"] = True
        assert len(receipts) == 1, {key: observations[key] for key in ("runtime_settings", "managed_status", "work", "attempts")}
        receipt = receipts[0]
        assert receipt["case_key"] == case_key and receipt["outcome"] == "APPLIED_CONTROL", receipts
        assert receipt["reason_code"] == "CONTROL_APPLIED" and receipt["resulting_publication_revision"] is None, receipts
        assert receipt["actor"] == "pgreact_mdm_worker" and receipt["action_revision"] == expected_revision, receipts
        assert receipt["control"] == expected_control, receipts
        assert receipt["request_body"]["action"] == "ESCALATE" and receipt["request_body"]["arguments"] == {"level": 2}, receipts
        delivered_at = timestamp(receipt["created_at"])
        assert delivered_at >= deadline, receipts
        if outage_mode:
            postmaster_after = timestamp(sql("SELECT pg_postmaster_start_time()"))
            assert postmaster_after > outage_postmaster_before and postmaster_after > deadline
            assert delivered_at >= postmaster_after >= resumed_at
            observations["outage_across_deadline"].update({
                "postmaster_after": postmaster_after.isoformat(),
                "delivered_at": delivered_at.isoformat(),
                "one_case_caught_up": True,
            })
            observations["checks"].append({
                "name": "outage-deadline-catchup-single-case", "result": "passed"})
        actual = cases()
        assert actual == expected, {"expected": expected, "actual": actual}
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                              "FROM public.policy_qualification_source s")) == source
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                              "FROM s1_audit.source s")) == temporal_source
        matches = json.loads(sql("SELECT jsonb_agg(to_jsonb(m)) FROM pgreact.matches m "
                                 "WHERE name='s1-future-idle'"))
        assert len(matches) == 1 and matches[0]["active"] and matches[0]["generation"] == 1, matches
        activation = matches[0]
        uuid.UUID(activation["activation_id"])
        uuid.UUID(activation["rule_version_id"])
        status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        work, attempts = observations["work"], observations["attempts"]
        assert [{k: v for k, v in row.items() if k not in ("work_id", "updated_at")}
                for row in work] == [{"kind": "rule", "name": "s1-future-idle", "version": "1",
                                     "state": "COMPLETED", "claimable": False}], work
        worker = "pg-react-managed/s1_idle/" + str(status["process"]["pid"])
        assert [{k: v for k, v in row.items() if k not in
                 ("execution_id", "episode_id", "started_at", "finished_at")}
                for row in attempts] == [{"attempt_no": 1, "worker_id": worker, "status": "COMPLETED",
                    "error_message": None, "error_code": None, "event_kind": "ACTIVATE",
                    "name": "s1-future-idle"}], attempts
        assert int(work[0]["work_id"]) == attempts[0]["episode_id"] > 0
        assert isinstance(attempts[0]["execution_id"], int) and attempts[0]["execution_id"] > 0
        started_at = timestamp(attempts[0]["started_at"])
        finished_at = timestamp(attempts[0]["finished_at"])
        updated_at = timestamp(work[0]["updated_at"])
        # MDM receipt creation and core attempt timestamps are separate writes.
        assert deadline <= started_at <= finished_at <= updated_at
        prior_case = next(row for row in before if row["case_key"] == case_key)
        expected_body = {
            "action": "ESCALATE", "arguments": {"level": 2}, "case_key": case_key,
            "binding_id": binding["binding_id"], "policy_revision": "s1-idle-feasibility",
            "expected_policy_digest": binding["policy_digest"],
            "expected_evidence_basis_digest": prior_case["evidence_basis_digest"][2:],
            "evaluation_ref": "pgreact:" + activation["activation_id"],
            "work_ref": "pgreact:" + activation["rule_version_id"] + ":" + work[0]["work_id"],
            **{"expected_" + name: prior_case[name] for name in ("review_version", "definition_version",
                "publication_revision", "stewardship_epoch", "action_revision")}}
        request_key = sql("SELECT encode(pgreact_mdm.intent_request_key('{}'::uuid,"
            "'s1-idle-feasibility',{},1,{},'escalate_level_2',2),'hex')".format(
                binding["binding_id"], int(case_key), int(prior_case["action_revision"])))
        request_digest = sql("SELECT encode(pgreact_mdm.intent_request_digest('" +
            json.dumps(expected_body).replace("'", "''") + "'::jsonb),'hex')")
        uuid.UUID(receipt["receipt_id"])
        expected_receipt = {"receipt_id": receipt["receipt_id"], "created_at": receipt["created_at"],
            "actor": "pgreact_mdm_worker", "selected_role_name": "pgreact_mdm_worker",
            "session_role_name": "mdm_s1_runtime", "action": "ESCALATE", "outcome": "APPLIED_CONTROL",
            "reason_code": "CONTROL_APPLIED", "control": expected_control, "case_key": case_key,
            "binding_id": binding["binding_id"], "binding_version": binding["binding_version"],
            "action_revision": expected_revision, "resulting_publication_revision": None,
            "request_body": expected_body, "request_key": "\\x" + request_key,
            "request_digest": "\\x" + request_digest}
        assert receipts == [expected_receipt], {"expected": expected_receipt, "actual": receipts}
        retained_receipts = json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                                          "FROM mdm_steward.policy_receipts_v1 r"))
        assert retained_receipts == observations["mdm_entry_receipts"] + [expected_receipt]
        failure_attempts = []
        end = time.monotonic() + 30
        while time.monotonic() < end:
            failure_attempts = json.loads(sql(
                "SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') "
                "FROM pgreact.attempts a WHERE name='s1-callback-failure'"))
            if failure_attempts:
                break
            time.sleep(0.2)
        observations["all_s1_work"] = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') "
            "FROM pgreact.work w WHERE name IN ('s1-callback-failure','s1-future-idle')"))
        observations["all_s1_attempts"] = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') "
            "FROM pgreact.attempts a WHERE name IN ('s1-callback-failure','s1-future-idle')"))
        assert len(failure_attempts) == 1, failure_attempts
        callback_failure = "injected registered S1 callback failure"
        assert {key: failure_attempts[0][key] for key in
                ("attempt_no", "status", "error_code", "error_message", "event_kind", "name")} == {
                    "attempt_no": 1, "status": "FAILED", "error_code": "P0001",
                    "error_message": callback_failure,
                    "event_kind": "ACTIVATE", "name": "s1-callback-failure"}, failure_attempts
        failure_work = json.loads(sql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') "
            "FROM pgreact.work w WHERE name='s1-callback-failure'"))
        assert [{key: row[key] for key in ("kind", "name", "version", "state", "claimable")}
                for row in failure_work] == [{"kind": "rule", "name": "s1-callback-failure",
                    "version": "1", "state": "FAILED", "claimable": False}], failure_work
        callback_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        failure_finished = timestamp(failure_attempts[0]["finished_at"])
        after_error_cycle = failure_finished + datetime.timedelta(seconds=1.5)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            callback_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            heartbeat = timestamp(callback_status["process"]["heartbeat_at"])
            if callback_status["process"]["state"] == "ready" and heartbeat > after_error_cycle:
                break
            time.sleep(0.2)
        assert callback_status["process"]["state"] == "ready", callback_status
        assert timestamp(callback_status["process"]["heartbeat_at"]) > after_error_cycle, callback_status
        logs = subprocess.run(["docker", "logs", "--tail", "1000", container],
                              capture_output=True, text=True, timeout=30)
        assert not logs.returncode, logs.stderr
        worker_logs = logs.stdout + logs.stderr
        callback_identity = ("registered-S1 callback entry rule_id=" +
                             observations["callback_failure_rule_ids"][0]["rule_id"] +
                             " session_user=mdm_s1_runtime "
                             "current_user=mdm_s1_runner")
        identity_at = worker_logs.find(callback_identity)
        assert failure_attempts[0]["error_message"] == callback_failure, failure_attempts
        assert identity_at >= 0, worker_logs
        assert "managed worker must begin each cycle as its configured login" not in worker_logs, worker_logs
        assert "managed cycle must restore its configured login role" not in worker_logs, worker_logs
        assert cases() == actual
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                              "FROM mdm_steward.policy_receipts_v1 r")) == retained_receipts
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                              "FROM public.policy_qualification_source s")) == source
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                              "FROM s1_audit.source s")) == temporal_source
        observations["callback_error_reset"] = {"managed_worker": True,
            "failed_registered_callback": "s1_audit.deliver(pgreact.activation_context,s1_audit.candidate)",
            "failure_attempts": failure_attempts, "failure_work": failure_work,
            "callback_identity": callback_identity, "post_error_managed_status": callback_status,
            "subsequent_cycle_after_error": True,
            "worker_role_identity": {"actor": receipt["actor"],
                "selected_role_name": receipt["selected_role_name"],
                "session_role_name": receipt["session_role_name"]},
            "public_state_unchanged": True, "transaction_path": "BackgroundWorker::transaction"}
        observations["checks"].append({"name": "callback-error-role-reset", "result": "passed"})
        # A receipt after one idle deadline is not sufficient: the real worker
        # must remain quiescent across *later* managed ticks. Preserve the full
        # durable control, request, receipt and worker-effect vectors while
        # allowing the process heartbeat and observational clock to advance.
        quiescence_sql = (
            "SELECT jsonb_build_object("
            "'cases',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY case_key),'[]') "
            "FROM mdm_steward.policy_cases_v1 c),"
            "'mdm_receipts',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id),'[]') "
            "FROM mdm_steward.policy_receipts_v1 r),"
            "'intent_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id,request_key),'[]') "
            "FROM pgreact_mdm.intent_requests r),"
            "'intent_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY episode_id,attempt_no),'[]') "
            "FROM pgreact_mdm.intent_attempts a),"
            "'rule_work',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') "
            "FROM pgreact.work w WHERE name='s1-future-idle'),"
            "'rule_attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') "
            "FROM pgreact.attempts a WHERE name='s1-future-idle'),"
            "'business_source',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') "
            "FROM public.policy_qualification_source s),"
            "'technical_source',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY case_key),'[]') "
            "FROM s1_audit.source s))"
        )
        quiescence_before = json.loads(sql(quiescence_sql))
        saved_requests = [
            row for row in quiescence_before["intent_requests"]
            if row["policy_revision"] == "s1-idle-feasibility" and row["case_key"] == case_key
        ]
        saved_attempts = [
            row for row in quiescence_before["intent_attempts"]
            if row["work_ref"] == expected_body["work_ref"]
        ]
        assert len(saved_requests) == len(saved_attempts) == 1, (saved_requests, saved_attempts)
        assert quiescence_before["cases"] == expected
        assert quiescence_before["mdm_receipts"] == retained_receipts
        assert quiescence_before["business_source"] == source
        assert quiescence_before["technical_source"] == temporal_source
        assert quiescence_before["rule_work"] == work
        assert quiescence_before["rule_attempts"] == attempts

        quiet_first_heartbeat = timestamp(callback_status["process"]["heartbeat_at"])
        quiet_deadline = quiet_first_heartbeat + datetime.timedelta(seconds=2)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            later_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = later_status.get("process") or {}
            heartbeat_value = process.get("heartbeat_at")
            if process.get("state") == "ready" and heartbeat_value and timestamp(heartbeat_value) > quiet_deadline:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker did not complete later idle cycles")
        quiescence_after = json.loads(sql(quiescence_sql))
        assert quiescence_after == quiescence_before, {
            "before": quiescence_before, "after": quiescence_after
        }
        observations["later_idle_cycles"] = {
            "first_heartbeat_at": quiet_first_heartbeat.isoformat(),
            "later_heartbeat_at": heartbeat_value,
            "exact_state_before": quiescence_before,
            "exact_state_after": quiescence_after,
            "unchanged": True,
        }
        observations["checks"].append({"name": "post-delivery-idle-quiescence", "result": "passed"})
        # A normal PostgreSQL restart must not turn an already delivered
        # escalation into another control. Validate a *new postmaster* and
        # a resumed ordinary managed worker, not just pg_isready.
        before_restart_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
        before_restart_state = quiescence_after
        before_restart_heartbeat = timestamp(later_status["process"]["heartbeat_at"])
        command("docker", "restart", container)
        end = time.monotonic() + 60
        restart_status = None
        restart_postmaster = None
        while time.monotonic() < end:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if ready.returncode:
                time.sleep(0.2)
                continue
            restart_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            restart_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = restart_status.get("process") or {}
            heartbeat = process.get("heartbeat_at")
            if (restart_postmaster > before_restart_postmaster
                    and process.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > before_restart_heartbeat):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "managed worker did not resume after a new PostgreSQL postmaster",
                "old_postmaster": before_restart_postmaster.isoformat(),
                "postmaster": str(restart_postmaster), "status": restart_status,
            })
        # Wait for more than one post-restart managed cycle, so a lazy replay
        # is observed before we assert unchanged durable state.
        resumed_heartbeat = timestamp(restart_status["process"]["heartbeat_at"])
        end = time.monotonic() + 30
        while time.monotonic() < end:
            restart_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = restart_status.get("process") or {}
            heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > resumed_heartbeat + datetime.timedelta(seconds=2)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker stopped advancing after restart")
        after_restart_state = json.loads(sql(quiescence_sql))
        assert after_restart_state == before_restart_state, {
            "error": "recovered managed worker recreated an already delivered effect",
            "before": before_restart_state, "after": after_restart_state,
        }
        observations["post_delivery_restart"] = {
            "postmaster_before": before_restart_postmaster.isoformat(),
            "postmaster_after": restart_postmaster.isoformat(),
            "heartbeat_before": before_restart_heartbeat.isoformat(),
            "heartbeat_after": heartbeat,
            "exact_state_before": before_restart_state,
            "exact_state_after": after_restart_state,
            "unchanged": True,
        }
        observations["checks"].append({"name": "post-delivery-restart-no-replay", "result": "passed"})
        if outage_mode:
            # This branch already proved the complete canonical MDM receipt,
            # actual action/case/source vector and worker role above. Record
            # the normal proof marker before ending this focused outage run.
            observations["checks"].append({
                "name": "future-idle-mdm-receipt", "result": "passed"})
            # Focused T49.06 proof: this run also checked post-delivery cycles
            # and a second real restart without replay. The ordinary full
            # audit runs separately to retain all later security/MDM vectors.
            observations["entry_decision"] = "FOCUSED_OUTAGE_QUALIFIED"
            return
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                              "FROM mdm_steward.policy_receipts_v1 r")) == retained_receipts
        sql("CREATE ROLE mdm_s1_runtime_no_set LOGIN")
        sql("GRANT CONNECT ON DATABASE s1_idle TO mdm_s1_runtime_no_set")
        sql("GRANT USAGE ON SCHEMA pgreact_api TO mdm_s1_runtime_no_set")
        sql("ALTER SYSTEM SET pg_react.worker_role = 'mdm_s1_runtime_no_set'")
        sql("ALTER SYSTEM SET pg_react.databases = 's1_idle'")
        command("docker", "restart", container)
        end = time.monotonic() + 20
        rejection_lines = []
        while time.monotonic() < end:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if not ready.returncode:
                logs = subprocess.run(["docker", "logs", "--tail", "200", container],
                                      capture_output=True, text=True, timeout=30)
                rejection_lines = [line for line in (logs.stdout + logs.stderr).splitlines()
                                   if "managed worker role must be a unique SET-capable function grantee" in line]
                if rejection_lines:
                    break
            time.sleep(0.2)
        assert rejection_lines, "worker without SET membership was not rejected by the managed path"
        assert sql("SELECT pg_catalog.pg_has_role('mdm_s1_runtime_no_set',"
                   "'pgreact_mdm_worker','SET')") == "f"
        assert sql("SELECT current_setting('pg_react.worker_role')") == "mdm_s1_runtime_no_set"
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
                              "FROM mdm_steward.policy_receipts_v1 r")) == retained_receipts
        assert cases() == actual
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) "
                              "FROM public.policy_qualification_source s")) == source
        assert json.loads(sql("SELECT jsonb_agg(to_jsonb(s) ORDER BY s.case_key) "
                              "FROM s1_audit.source s")) == temporal_source
        assert json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY work_id),'[]') "
                              "FROM pgreact.work w WHERE name='s1-future-idle'")) == work
        assert json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY execution_id),'[]') "
                              "FROM pgreact.attempts a WHERE name='s1-future-idle'")) == attempts
        observations["no_set_membership"] = {"worker_login": "mdm_s1_runtime_no_set",
            "configured_role": "pgreact_mdm_worker", "set_membership": False,
            "rejection": rejection_lines[-1], "public_state_unchanged": True}
        observations["checks"].append({"name": "worker-missing-set-membership", "result": "passed"})
        observations.update(receipt_expected=expected_receipt, matches=matches, idle_binding=binding)
        observations.update(cases_actual=actual, receipts=receipts,
                            deadline_to_receipt_seconds=(delivered_at - deadline).total_seconds(),
                            managed_status=json.loads(sql("SELECT pgreact_api.managed_status()")),
                            deadline_history=json.loads(sql("SELECT pgreact_api.deadline_history('s1-future-idle')")))
        observations["checks"].append({"name": "future-idle-mdm-receipt", "result": "passed"})
        # Separate authority-level regression after the proven worker delivery,
        # restart and privilege tests. This intentionally changes only the
        # MDM case via its authorized human API, then sends two *new* keys
        # through the authenticated worker interface. It does not claim that
        # React emitted those independent work items.
        fixture("human-reduction-crosskey",
                "/work/tests/integrations/pg-mdm/time/human-reduction-crosskey.sql", "s1_idle")
        cross_key = json.loads(sql("SELECT vector FROM s1_cross_key.evidence"))
        assert cross_key["exact"] and len(cross_key["denial_receipts"]) == 2, cross_key
        observations["human_reduction_crosskey"] = cross_key
        observations["cases_after_human_reduction"] = cases()
        observations["receipts_after_human_reduction"] = json.loads(sql(
            "SELECT jsonb_agg(to_jsonb(r) ORDER BY created_at,receipt_id) "
            "FROM mdm_steward.policy_receipts_v1 r"))

        # After the human reduced level 2 -> 1 and MDM retained its two
        # terminal cross-key denials, put the legitimate managed login back in
        # service. A new worker must not manufacture any additional control,
        # receipt, immutable request/attempt, work, or source changes merely
        # because that previously applied level is again visible as next.
        human_quiet_before = json.loads(sql(quiescence_sql))
        assert human_quiet_before["cases"] == observations["cases_after_human_reduction"]
        assert human_quiet_before["mdm_receipts"] == observations["receipts_after_human_reduction"]
        assert human_quiet_before["business_source"] == source
        assert human_quiet_before["technical_source"] == temporal_source
        sql("ALTER SYSTEM SET pg_react.worker_role = 'mdm_s1_runtime'")
        postmaster_before_human = timestamp(sql("SELECT pg_postmaster_start_time()"))
        command("docker", "restart", container)
        end = time.monotonic() + 60
        human_worker_status = None
        human_postmaster = None
        while time.monotonic() < end:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if ready.returncode:
                time.sleep(0.2)
                continue
            human_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            human_worker_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            worker = human_worker_status.get("process") or {}
            if (human_postmaster > postmaster_before_human
                    and worker.get("state") == "ready" and worker.get("heartbeat_at")):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "authenticated managed worker did not resume after human reduction",
                "status": human_worker_status, "postmaster": str(human_postmaster)
            })
        human_heartbeat_first = timestamp(human_worker_status["process"]["heartbeat_at"])
        end = time.monotonic() + 30
        while time.monotonic() < end:
            human_worker_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            worker = human_worker_status.get("process") or {}
            heartbeat = worker.get("heartbeat_at")
            if (worker.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > human_heartbeat_first + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker did not advance after human reduction")
        human_quiet_after = json.loads(sql(quiescence_sql))
        assert human_quiet_after == human_quiet_before, {
            "error": "human-reduced occurrence generated another durable effect",
            "before": human_quiet_before, "after": human_quiet_after
        }
        observations["post_human_managed_convergence"] = {
            "postmaster": human_postmaster.isoformat(),
            "heartbeat_first": human_heartbeat_first.isoformat(),
            "heartbeat_after": heartbeat,
            "complete_before": human_quiet_before,
            "complete_after": human_quiet_after,
            "unchanged": True,
        }
        observations["checks"].append({"name": "post-human-managed-convergence", "result": "passed"})

        # Two distinct authenticated MDM worker requests must contend for the
        # *same* case-row lock. Hold that row in an independent transaction,
        # prove BOTH callers are waiting on PostgreSQL locks, then release it.
        # This tests concurrency of the MDM authority, not React claim races.
        # Reuse MDM's previously persisted canonical denial body/tokens rather
        # than manufacturing fresh policy or revision values.
        deny_template = cross_key["denial_receipts"][0]
        assert all(row["reason_code"] == "ESCALATION_LEVEL_ALREADY_APPLIED"
                   for row in cross_key["denial_receipts"])
        assert deny_template["request_body"]["case_key"] == case_key
        concurrent_before = json.loads(sql(quiescence_sql))

        def sql_literal(value):
            return "'" + str(value).replace("'", "''") + "'"

        concurrent_requests = {}
        worker_sessions = []
        holder = None
        observed_waits = []
        try:
            holder = subprocess.Popen([
                "docker", "exec", "-i", container, "psql", "-XAtq", "-U", "postgres",
                "-d", "s1_idle", "-v", "ON_ERROR_STOP=1"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            holder.stdin.write(
                "SET application_name = 'react11-case-lock-holder';\n"
                "BEGIN;\n"
                f"SELECT case_key FROM mdm_steward.policy_cases_v1 "
                f"WHERE case_key = {int(case_key)} FOR UPDATE;\n")
            holder.stdin.flush()
            end = time.monotonic() + 20
            while time.monotonic() < end:
                held = sql("SELECT count(*) FROM pg_stat_activity "
                           "WHERE application_name = 'react11-case-lock-holder' "
                           "AND state = 'idle in transaction'")
                if held == "1":
                    break
                if holder.poll() is not None:
                    raise AssertionError("concurrency lock holder exited before case lock")
                time.sleep(0.1)
            else:
                raise AssertionError("concurrency lock holder did not acquire case row")

            for suffix in ("ee", "ef"):
                key_hex = suffix * 32
                body = dict(deny_template["request_body"])
                body["evaluation_ref"] = "concurrent-" + suffix
                body["work_ref"] = "concurrent-work-" + suffix
                concurrent_requests[suffix] = (key_hex, body)
                statement = (
                    "SET application_name = " + sql_literal("react11-worker-" + suffix) + "; "
                    "SET SESSION AUTHORIZATION mdm_s1_runtime; "
                    "SET ROLE pgreact_mdm_worker; "
                    "SELECT row_to_json(result) FROM mdm_steward.submit_policy_intent("
                    + sql_literal(deny_template["binding_id"]) + "::uuid, "
                    + "decode(" + sql_literal(key_hex) + ", 'hex'), "
                    + str(int(case_key)) + ", 'ESCALATE', "
                    + sql_literal(json.dumps(body["arguments"])) + "::jsonb, "
                    + ", ".join(str(int(body[k])) for k in (
                        "expected_review_version", "expected_definition_version",
                        "expected_publication_revision", "expected_stewardship_epoch"))
                    + ", decode(" + sql_literal(body["expected_evidence_basis_digest"]) + ", 'hex'), "
                    + str(int(body["expected_action_revision"])) + ", decode("
                    + sql_literal(body["expected_policy_digest"]) + ", 'hex'), "
                    + ", ".join(sql_literal(body[k]) for k in (
                        "policy_revision", "evaluation_ref", "work_ref"))
                    + ") AS result;"
                )
                worker_sessions.append((suffix, subprocess.Popen([
                    "docker", "exec", container, "psql", "-XAtq", "-U", "postgres",
                    "-d", "s1_idle", "-v", "ON_ERROR_STOP=1", "-c", statement],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)))

            end = time.monotonic() + 25
            while time.monotonic() < end:
                observed_waits = json.loads(sql(
                    "SELECT COALESCE(jsonb_agg(jsonb_build_object("
                    "'app',application_name,'wait',wait_event_type) "
                    "ORDER BY application_name),'[]') "
                    "FROM pg_stat_activity "
                    "WHERE application_name IN ('react11-worker-ee','react11-worker-ef')"))
                if observed_waits == [
                    {"app": "react11-worker-ee", "wait": "Lock"},
                    {"app": "react11-worker-ef", "wait": "Lock"},
                ]:
                    break
                if any(process.poll() is not None for _, process in worker_sessions):
                    raise AssertionError({"error": "concurrent worker exited before lock barrier",
                                          "observed": observed_waits})
                time.sleep(0.1)
            else:
                raise AssertionError({"error": "both requests did not contend on case lock",
                                      "observed": observed_waits})

            holder.stdin.write("COMMIT;\n\\q\n")
            holder.stdin.flush()
            holder_stdout, holder_stderr = holder.communicate(timeout=20)
            assert holder.returncode == 0, (holder_stdout, holder_stderr)
            concurrent_responses = {}
            for suffix, process in worker_sessions:
                stdout, stderr = process.communicate(timeout=30)
                assert process.returncode == 0, {"caller": suffix, "stderr": stderr}
                concurrent_responses[suffix] = json.loads(stdout.strip())
        finally:
            for _, process in worker_sessions:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
            if holder is not None and holder.poll() is None:
                holder.kill()
                holder.communicate(timeout=10)

        concurrent_after = json.loads(sql(quiescence_sql))
        for state_name, before_vector in concurrent_before.items():
            if state_name != "mdm_receipts":
                assert concurrent_after[state_name] == before_vector, {
                    "state": state_name, "before": before_vector,
                    "after": concurrent_after[state_name],
                }
        existing_ids = {r["receipt_id"] for r in concurrent_before["mdm_receipts"]}
        new_receipts = [r for r in concurrent_after["mdm_receipts"]
                        if r["receipt_id"] not in existing_ids]
        assert len(new_receipts) == 2, new_receipts
        assert [r for r in concurrent_after["mdm_receipts"]
                if r["receipt_id"] in existing_ids] == concurrent_before["mdm_receipts"]
        receipt_by_key = {r["request_key"]: r for r in new_receipts}
        assert set(receipt_by_key) == {"\\x" + suffix * 32 for suffix in ("ee", "ef")}
        expected_receipts = []
        for suffix in ("ee", "ef"):
            key_hex, body = concurrent_requests[suffix]
            saved = receipt_by_key["\\x" + key_hex]
            response = concurrent_responses[suffix]
            assert response["receipt_id"] == saved["receipt_id"]
            assert response["outcome"] == "ACTION_DENIED"
            assert response["reason_code"] == "ESCALATION_LEVEL_ALREADY_APPLIED"
            assert response["case_key"] == case_key
            assert response["action_revision"] == body["expected_action_revision"]
            assert response["control"] == saved["control"]
            assert response["resulting_publication_revision"] is None
            uuid.UUID(saved["receipt_id"])
            assert timestamp(saved["created_at"]).tzinfo is not None
            digest = sql("SELECT encode(pgreact_mdm.intent_request_digest("
                         + sql_literal(json.dumps(body)) + "::jsonb),'hex')")
            expected_saved = dict(deny_template)
            expected_saved.update({
                "receipt_id": saved["receipt_id"],
                "created_at": saved["created_at"],
                "request_key": "\\x" + key_hex,
                "request_digest": "\\x" + digest,
                "request_body": body,
            })
            assert saved == expected_saved, {"expected": expected_saved, "actual": saved}
            expected_receipts.append(expected_saved)
        assert concurrent_after["cases"] == human_quiet_before["cases"]
        assert concurrent_after["business_source"] == source
        assert concurrent_after["technical_source"] == temporal_source
        observations["concurrent_cross_key_denials"] = {
            "observed_lock_waits": observed_waits,
            "responses": concurrent_responses,
            "before": concurrent_before,
            "after": concurrent_after,
            "new_exact_receipts": expected_receipts,
        }
        observations["checks"].append({"name": "concurrent-cross-key-denials", "result": "passed"})
        # A subsequent human edit advances only the case action revision.
        # Captured pre-edit tokens must be rejected as stale, while current
        # tokens for the previously automated-applied level must be denied by
        # retained MDM occurrence history. Exact immutable React work and
        # public source vectors are asserted by the SQL fixture.
        fixture("human-stale-after-concurrency",
                "/work/tests/integrations/pg-mdm/time/human-stale-after-concurrency.sql",
                "s1_idle")
        stale_human = json.loads(sql("SELECT vector FROM s1_stale.evidence"))
        assert stale_human["exact"] and stale_human["unchanged_adapter_and_sources"], stale_human
        observations["stale_after_human_edit"] = stale_human
        observations["checks"].append({
            "name": "stale-vs-current-human-token", "result": "passed"
        })

        # Reuse MDM's real resolution/publication recurrence fixture, where
        # the same issue_key was reopened as a different case_key. The original
        # applied-level history must remain scoped to its own occurrence, not
        # block a permitted first level-2 application in the new occurrence.
        # This test invokes the real MDM human/worker APIs: it does not claim
        # React's ordinary managed worker discovered the new case.
        before_recurrence = json.loads(sql(quiescence_sql))
        fixture("recurrence-independent",
                "/work/tests/integrations/pg-mdm/time/recurrence-independent.sql",
                "s1_idle")
        recurrence = json.loads(sql("SELECT vector FROM s1_recurrence.evidence"))
        assert recurrence["exact"] and recurrence["old_receipts_unchanged"], recurrence
        assert recurrence["old_case_key"] != recurrence["new_case_key"], recurrence
        after_recurrence = json.loads(sql(quiescence_sql))
        for category in ("intent_requests", "intent_attempts",
                         "rule_work", "rule_attempts",
                         "business_source", "technical_source"):
            assert after_recurrence[category] == before_recurrence[category], category
        assert len(after_recurrence["mdm_receipts"]) == len(before_recurrence["mdm_receipts"]) + 1
        assert len(after_recurrence["cases"]) == len(before_recurrence["cases"])
        assert all(before == after for before, after in zip(
            before_recurrence["cases"], after_recurrence["cases"])
            if before["case_key"] != recurrence["new_case_key"])
        observations["recurrence_independent"] = recurrence
        observations["checks"].append({
            "name": "recurrence-new-occurrence", "result": "passed"
        })
        # After the real recurrence's authorized MDM control, keep the
        # ordinary managed worker running. Because the enrolled React rule
        # selects a different case_key, a subsequent managed poll must neither
        # replay the new occurrence nor mutate unrelated old cases/sources.
        # This is an observation-only quiescence test, not proof that the
        # React scheduler autonomously enrolls every new MDM occurrence.
        recurrence_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        process = recurrence_status.get("process") or {}
        assert process.get("state") == "ready" and process.get("heartbeat_at"), recurrence_status
        recurrence_heartbeat = timestamp(process["heartbeat_at"])
        end = time.monotonic() + 35
        observed_status = None
        while time.monotonic() < end:
            observed_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = observed_status.get("process") or {}
            observed_heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and observed_heartbeat
                    and timestamp(observed_heartbeat) >
                    recurrence_heartbeat + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "managed worker did not complete post-recurrence cycles",
                "initial": recurrence_status, "last": observed_status
            })
        after_recurrence_cycles = json.loads(sql(quiescence_sql))
        assert after_recurrence_cycles == after_recurrence, {
            "error": "post-recurrence managed cycle changed durable state",
            "before": after_recurrence, "after": after_recurrence_cycles
        }
        observations["post_recurrence_worker_quiescence"] = {
            "heartbeat_before": recurrence_heartbeat.isoformat(),
            "heartbeat_after": observed_heartbeat,
            "full_before": after_recurrence,
            "full_after": after_recurrence_cycles,
            "unchanged": True
        }
        observations["checks"].append({
            "name": "post-recurrence-worker-quiescence", "result": "passed"
        })

        # A cold PostgreSQL restart after the genuine recurrence must retain
        # BOTH occurrence populations and the newly applied exact MDM receipt.
        # Observe a different postmaster and multiple resumed managed-worker
        # cycles, then compare the entire durable state, not just counts.
        before_recurrence_restart = json.loads(sql(quiescence_sql))
        old_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
        old_heartbeat = timestamp(observed_heartbeat)
        command("docker", "restart", container)
        restart_end = time.monotonic() + 60
        restarted_status = None
        new_postmaster = None
        while time.monotonic() < restart_end:
            readiness = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres"],
                capture_output=True)
            if readiness.returncode:
                time.sleep(0.2)
                continue
            new_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            restarted_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = restarted_status.get("process") or {}
            heartbeat = process.get("heartbeat_at")
            if (new_postmaster > old_postmaster
                    and process.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > old_heartbeat):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "managed worker failed to resume after recurrence restart",
                "old_postmaster": old_postmaster.isoformat(),
                "new_postmaster": str(new_postmaster),
                "status": restarted_status,
            })
        resumed_at = timestamp(restarted_status["process"]["heartbeat_at"])
        restart_end = time.monotonic() + 35
        while time.monotonic() < restart_end:
            restarted_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = restarted_status.get("process") or {}
            heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > resumed_at + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker did not complete later cycles after recurrence restart")
        after_recurrence_restart = json.loads(sql(quiescence_sql))
        assert after_recurrence_restart == before_recurrence_restart, {
            "error": "recurrence history or worker effects changed after restart",
            "before": before_recurrence_restart,
            "after": after_recurrence_restart,
        }
        assert any(case["case_key"] == recurrence["old_case_key"]
                   for case in after_recurrence_restart["cases"])
        assert any(case["case_key"] == recurrence["new_case_key"]
                   and case["escalation_level"] == 2
                   for case in after_recurrence_restart["cases"])
        assert sum(r["case_key"] == recurrence["new_case_key"]
                   and r["action"] == "ESCALATE" and r["outcome"] == "APPLIED_CONTROL"
                   for r in after_recurrence_restart["mdm_receipts"]) == 1
        observations["post_recurrence_restart"] = {
            "old_postmaster": old_postmaster.isoformat(),
            "new_postmaster": new_postmaster.isoformat(),
            "first_resumed_heartbeat": resumed_at.isoformat(),
            "later_heartbeat": heartbeat,
            "full_before": before_recurrence_restart,
            "full_after": after_recurrence_restart,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "post-recurrence-restart-no-replay", "result": "passed"
        })
        # A permitted second level does not imply authorization to move to
        # level 3: enforce the exact active MDM binding's maximum, after the
        # true recurrence and its cold-restart proof. This invokes MDM's
        # authenticated worker entrypoint; it does not synthesize React work.
        fixture("recurrence-maximum",
                "/work/tests/integrations/pg-mdm/time/recurrence-maximum.sql",
                "s1_idle")
        maximum = json.loads(sql("SELECT vector FROM s1_maximum.evidence"))
        assert maximum["exact"] and maximum["state_unchanged"], maximum
        assert maximum["binding_maximum"] == 2, maximum
        assert maximum["case_key"] == recurrence["new_case_key"], maximum
        observations["recurrence_maximum"] = maximum
        observations["checks"].append({
            "name": "recurrence-max-level-denial", "result": "passed"
        })
        # The bound's terminal denial must not create another MDM control
        # when the ordinary managed worker continues to poll. Require
        # observable worker progress rather than sleeping and assuming it.
        max_before = json.loads(sql(quiescence_sql))
        max_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        max_worker = max_status.get("process") or {}
        assert max_worker.get("state") == "ready" and max_worker.get("heartbeat_at"), max_status
        max_heartbeat = timestamp(max_worker["heartbeat_at"])
        deadline = time.monotonic() + 35
        max_last = None
        while time.monotonic() < deadline:
            max_last = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = max_last.get("process") or {}
            heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > max_heartbeat + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({"error": "worker stalled after maximum-level denial",
                                  "before": max_status, "after": max_last})
        max_after = json.loads(sql(quiescence_sql))
        assert max_after == max_before, {
            "error": "maximum-level denial caused delayed managed effects",
            "before": max_before, "after": max_after,
        }
        assert sum(row["case_key"] == recurrence["new_case_key"]
                   and row["outcome"] == "APPLIED_CONTROL"
                   and row["action"] == "ESCALATE"
                   for row in max_after["mdm_receipts"]) == 1
        assert sum(row["case_key"] == recurrence["new_case_key"]
                   and row["outcome"] == "LIMIT_EXCEEDED"
                   and row["reason_code"] == "ESCALATION_LIMIT"
                   for row in max_after["mdm_receipts"]) == 1
        observations["post_maximum_managed_quiescence"] = {
            "heartbeat_before": max_heartbeat.isoformat(),
            "heartbeat_after": heartbeat,
            "full_before": max_before,
            "full_after": max_after,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "post-maximum-managed-quiescence", "result": "passed"
        })
        # Recovery after a terminal limit denial: the original applied
        # recurrence receipt and the denied attempt must both survive another
        # postmaster epoch, with no fresh work emitted by the ordinary worker.
        max_restart_before = json.loads(sql(quiescence_sql))
        max_start_before = timestamp(sql("SELECT pg_postmaster_start_time()"))
        max_heartbeat_before = timestamp(heartbeat)
        command("docker", "restart", container)
        end = time.monotonic() + 60
        max_restart_status = None
        max_start_after = None
        while time.monotonic() < end:
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if ready.returncode:
                time.sleep(0.2)
                continue
            max_start_after = timestamp(sql("SELECT pg_postmaster_start_time()"))
            max_restart_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            proc = max_restart_status.get("process") or {}
            hb = proc.get("heartbeat_at")
            if (max_start_after > max_start_before
                    and proc.get("state") == "ready" and hb
                    and timestamp(hb) > max_heartbeat_before):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "worker unavailable after maximum-denial restart",
                "old_start": max_start_before.isoformat(),
                "new_start": str(max_start_after),
                "status": max_restart_status,
            })
        max_resumed = timestamp(max_restart_status["process"]["heartbeat_at"])
        end = time.monotonic() + 35
        while time.monotonic() < end:
            max_restart_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            proc = max_restart_status.get("process") or {}
            hb = proc.get("heartbeat_at")
            if (proc.get("state") == "ready" and hb
                    and timestamp(hb) > max_resumed + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("worker did not complete post-denial restart cycles")
        max_restart_after = json.loads(sql(quiescence_sql))
        assert max_restart_after == max_restart_before, {
            "error": "restart replayed or altered terminal maximum denial",
            "before": max_restart_before, "after": max_restart_after,
        }
        assert sum(r["case_key"] == recurrence["new_case_key"]
                   and r["outcome"] == "APPLIED_CONTROL"
                   and r["action"] == "ESCALATE"
                   for r in max_restart_after["mdm_receipts"]) == 1
        assert sum(r["case_key"] == recurrence["new_case_key"]
                   and r["outcome"] == "LIMIT_EXCEEDED"
                   and r["reason_code"] == "ESCALATION_LIMIT"
                   for r in max_restart_after["mdm_receipts"]) == 1
        observations["post_maximum_restart"] = {
            "postmaster_before": max_start_before.isoformat(),
            "postmaster_after": max_start_after.isoformat(),
            "first_resumed_heartbeat": max_resumed.isoformat(),
            "later_heartbeat": hb,
            "full_before": max_restart_before,
            "full_after": max_restart_after,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "post-maximum-restart-no-replay", "result": "passed"
        })
        # The MDM entity owner explicitly pauses the binding; fresh worker
        # requests must be denied by the MDM pause barrier even if their
        # captured case tokens are current. This runs last to avoid
        # weakening the earlier live-binding coverage.
        fixture("pause-barrier", "/work/tests/integrations/pg-mdm/time/pause-barrier.sql",
                "s1_idle")
        paused = json.loads(sql("SELECT vector FROM s1_pause.evidence"))
        assert paused["exact"] and paused["state_unchanged"], paused
        observations["pause_barrier"] = paused
        observations["checks"].append({
            "name": "authorized-pause-barrier", "result": "passed"
        })
        # The operator-owned paused binding must remain paused after a real
        # PostgreSQL restart, and the enrolled worker must not manufacture
        # new work or any MDM control while it resumes heartbeat cycles.
        pause_before = json.loads(sql(quiescence_sql))
        pause_binding_before = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert all(b["binding_id"] != paused["binding_id"]
                   for b in pause_binding_before["runtime"])
        previous_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
        previous_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        previous_heartbeat = timestamp(previous_status["process"]["heartbeat_at"])
        command("docker", "restart", container)
        until = time.monotonic() + 60
        after_postmaster = None
        resumed_status = None
        while time.monotonic() < until:
            probe = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True)
            if probe.returncode:
                time.sleep(0.2)
                continue
            after_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            resumed_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = resumed_status.get("process") or {}
            new_heartbeat = process.get("heartbeat_at")
            if (after_postmaster > previous_postmaster
                    and process.get("state") == "ready" and new_heartbeat
                    and timestamp(new_heartbeat) > previous_heartbeat):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "managed worker did not resume after operator pause",
                "before": previous_status, "after": resumed_status
            })
        first_resumed = timestamp(new_heartbeat)
        until = time.monotonic() + 35
        while time.monotonic() < until:
            resumed_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = resumed_status.get("process") or {}
            new_heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and new_heartbeat
                    and timestamp(new_heartbeat) > first_resumed + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("managed worker did not progress after paused-binding restart")
        pause_after = json.loads(sql(quiescence_sql))
        pause_binding_after = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert pause_after == pause_before, {
            "error": "paused binding generated an effect after cold restart",
            "before": pause_before, "after": pause_after
        }
        assert pause_binding_after == pause_binding_before, {
            "error": "binding runtime unexpectedly resumed after restart",
            "before": pause_binding_before, "after": pause_binding_after
        }
        observations["post_pause_restart"] = {
            "postmaster_before": previous_postmaster.isoformat(),
            "postmaster_after": after_postmaster.isoformat(),
            "heartbeat_first": first_resumed.isoformat(),
            "heartbeat_later": new_heartbeat,
            "full_before": pause_before, "full_after": pause_after,
            "binding_before": pause_binding_before, "binding_after": pause_binding_after,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "paused-binding-restart-no-replay", "result": "passed"
        })

        # Reconcile only after cold-restart durability was established.
        # An old paused request must retain its original BINDING_PAUSED
        # receipt, while a NEW key observes the active binding's maximum.
        fixture("resume-after-pause",
                "/work/tests/integrations/pg-mdm/time/resume-after-pause.sql", "s1_idle")
        resumed = json.loads(sql("SELECT vector FROM s1_resume.evidence"))
        assert resumed["exact"] and resumed["cases_and_react_unchanged"], resumed
        assert resumed["binding_id"] == paused["binding_id"], resumed
        assert resumed["reactivated_runtime_version"] > resumed["paused_runtime_version"]
        assert resumed["original_paused_receipt_id"] == resumed["replayed_paused_receipt_id"]
        observations["resume_after_pause"] = resumed
        observations["checks"].append({
            "name": "authorized-pause-resume-immutable-receipts", "result": "passed"
        })

        # React's original enrolled single-case rule must not emit duplicate
        # work when the binding becomes active again. Observe actual managed
        # cycles (not just a delay) and compare complete durable state.
        resumed_quiet_before = json.loads(sql(quiescence_sql))
        resumed_runtime_before = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert any(r["binding_id"] == resumed["binding_id"]
                   and r["runtime_version"] == resumed["reactivated_runtime_version"]
                   for r in resumed_runtime_before["runtime"]), resumed_runtime_before
        resumed_worker = json.loads(sql("SELECT pgreact_api.managed_status()"))
        process = resumed_worker.get("process") or {}
        assert process.get("state") == "ready" and process.get("heartbeat_at"), resumed_worker
        start_heartbeat = timestamp(process["heartbeat_at"])
        until = time.monotonic() + 35
        while time.monotonic() < until:
            resumed_worker = json.loads(sql("SELECT pgreact_api.managed_status()"))
            process = resumed_worker.get("process") or {}
            later_heartbeat = process.get("heartbeat_at")
            if (process.get("state") == "ready" and later_heartbeat
                    and timestamp(later_heartbeat) > start_heartbeat + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({"error": "managed worker stalled after binding reconciliation",
                                  "status": resumed_worker})
        resumed_quiet_after = json.loads(sql(quiescence_sql))
        resumed_runtime_after = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert resumed_quiet_after == resumed_quiet_before, {
            "error": "managed cycles after binding resume changed durable state",
            "before": resumed_quiet_before, "after": resumed_quiet_after,
        }
        assert resumed_runtime_after == resumed_runtime_before, {
            "error": "binding state changed on managed cycles after resume",
            "before": resumed_runtime_before, "after": resumed_runtime_after,
        }
        observations["post_resume_managed_quiescence"] = {
            "heartbeat_before": start_heartbeat.isoformat(),
            "heartbeat_after": later_heartbeat,
            "full_before": resumed_quiet_before,
            "full_after": resumed_quiet_after,
            "binding_before": resumed_runtime_before,
            "binding_after": resumed_runtime_after,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "post-resume-managed-quiescence", "result": "passed"
        })

        # A second operator using the *old* paused runtime version must
        # fail to pause OR resume the now-active binding. MDM's optimistic
        # fence must leave all binding/runtime, case, receipt, React work
        # and business/technical source vectors byte-for-byte unchanged.
        fixture("resume-stale-version",
                "/work/tests/integrations/pg-mdm/time/resume-stale-version.sql",
                "s1_idle")
        stale_version = json.loads(sql("SELECT vector FROM s1_stale_runtime.evidence"))
        assert stale_version["exact"] and stale_version["complete_state_unchanged"], stale_version
        assert stale_version["binding_id"] == resumed["binding_id"]
        assert stale_version["old_version"] == resumed["paused_runtime_version"]
        assert stale_version["active_version"] == resumed["reactivated_runtime_version"]
        assert stale_version["errors"]["both_rejected"], stale_version
        observations["stale_operator_runtime_version"] = stale_version
        observations["checks"].append({
            "name": "stale-operator-runtime-version", "result": "passed"
        })
        # The active binding and the exact rejected stale operator attempts
        # must survive another true PostgreSQL postmaster epoch. Observe
        # multiple resumed managed-worker cycles, then compare complete
        # persisted cases, receipts, runtime binding rows, and React/source
        # work to rule out a delayed replay or binding-state regression.
        final_before = json.loads(sql(quiescence_sql))
        final_binding_before = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert any(item["binding_id"] == resumed["binding_id"]
                   and item["runtime_version"] == resumed["reactivated_runtime_version"]
                   for item in final_binding_before["runtime"]), final_binding_before
        final_start = timestamp(sql("SELECT pg_postmaster_start_time()"))
        final_status = json.loads(sql("SELECT pgreact_api.managed_status()"))
        assert final_status["process"]["state"] == "ready", final_status
        final_heartbeat = timestamp(final_status["process"]["heartbeat_at"])
        command("docker", "restart", container)
        end = time.monotonic() + 60
        restarted = None
        new_postmaster = None
        while time.monotonic() < end:
            probe = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres"],
                capture_output=True)
            if probe.returncode:
                time.sleep(0.2)
                continue
            new_postmaster = timestamp(sql("SELECT pg_postmaster_start_time()"))
            restarted = json.loads(sql("SELECT pgreact_api.managed_status()"))
            worker = restarted.get("process") or {}
            heartbeat = worker.get("heartbeat_at")
            if (new_postmaster > final_start and worker.get("state") == "ready"
                    and heartbeat and timestamp(heartbeat) > final_heartbeat):
                break
            time.sleep(0.2)
        else:
            raise AssertionError({
                "error": "resumed binding did not recover after restart",
                "postmaster_before": final_start.isoformat(),
                "postmaster_after": str(new_postmaster),
                "status": restarted,
            })
        restart_heartbeat_first = timestamp(restarted["process"]["heartbeat_at"])
        end = time.monotonic() + 35
        while time.monotonic() < end:
            restarted = json.loads(sql("SELECT pgreact_api.managed_status()"))
            worker = restarted.get("process") or {}
            heartbeat = worker.get("heartbeat_at")
            if (worker.get("state") == "ready" and heartbeat
                    and timestamp(heartbeat) > restart_heartbeat_first
                    + datetime.timedelta(seconds=3)):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("resumed binding worker did not complete later restart cycles")
        final_after = json.loads(sql(quiescence_sql))
        final_binding_after = json.loads(sql(
            "SELECT jsonb_build_object("
            "'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_bindings b),"
            "'runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM pgreact_mdm.policy_intent_runtime r),"
            "'mdm_runtime',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY binding_id),'[]')"
            " FROM mdm_internal.policy_binding_runtime r))"))
        assert final_after == final_before, {
            "error": "post-resume restart replayed or changed durable state",
            "before": final_before, "after": final_after,
        }
        assert final_binding_after == final_binding_before, {
            "error": "post-resume restart changed binding version or state",
            "before": final_binding_before, "after": final_binding_after,
        }
        observations["post_resume_restart"] = {
            "postmaster_before": final_start.isoformat(),
            "postmaster_after": new_postmaster.isoformat(),
            "first_heartbeat": restart_heartbeat_first.isoformat(),
            "later_heartbeat": heartbeat,
            "full_before": final_before,
            "full_after": final_after,
            "bindings_before": final_binding_before,
            "bindings_after": final_binding_after,
            "unchanged": True,
        }
        observations["checks"].append({
            "name": "post-resume-restart-no-replay", "result": "passed"
        })
        qualify_recovery(quiescence_sql)
        observations["entry_decision"] = "QUALIFICATION_INCOMPLETE"
        observations["remaining_gates"] = profile["remaining_measurements"]
        print("PASS: future idle deadline -> actual MDM receipt; registered callback failure and role reset; complete case/source vectors", flush=True)
    except BaseException as error:
        observations["failure"] = str(error)
        if created:
            if (observations["checks"] and observations["checks"][-1] == {"name": "idle-setup", "result": "failed"}
                    and sql("SELECT to_regclass('s1_audit.before_registration') IS NOT NULL") == "t"):
                before = json.loads(sql("SELECT vector FROM s1_audit.before_registration"))
                after = json.loads(sql("SELECT s1_audit.registration_state()"))
                observations.update(entry_decision="STOP", registration_before=before,
                    registration_after=after, registration_state_unchanged=before == after,
                    idle_case_delivered=False,
                    stop_reason="Direct authorized MDM-source deadline registration fails inside pgtrickle.create_stream_table; the successful technical-source idle proof does not qualify this source path.",
                    conditional_work_not_performed=["typed managed temporal registration implementation",
                        "bounded catch-up", "deduplication convergence", "diagnostics/recovery/concurrency acceptance"])
            logs = subprocess.run(["docker", "logs", "--tail", "100", container],
                                  capture_output=True, text=True, timeout=30)
            observations["failure_logs"] = logs.stdout + logs.stderr
            recovery_logs = subprocess.run(
                ["docker", "exec", container, "cat", "/tmp/s1-recovered.log"],
                capture_output=True, text=True, timeout=30)
            if recovery_logs.returncode == 0:
                observations["recovery_failure_logs"] = recovery_logs.stdout
        raise
    finally:
        (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        if created:
            command("docker", "rm", "--force", "--volumes", container)


if __name__ == "__main__":
    main()
