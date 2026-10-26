"""Real MDM recurrence delivered only by the ordinary PostgreSQL worker."""
import copy
import datetime
import json
import time


def qualify(sql, command, fixture, container, observations):
    fixture("autonomous-setup", "/work/tests/integrations/pg-mdm/time/autonomous-recurrence.sql", "s1_idle")
    read = lambda query: json.loads(sql(query))
    state = lambda: read("SELECT s1_auto.state()")
    before = state()
    original = read("SELECT original_key FROM s1_auto.issue")
    binding = read("SELECT to_jsonb(b) FROM pgreact_mdm.policy_intent_bindings b WHERE enabled")

    def wait_for(predicate, description, seconds=45):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            actual = state()
            if predicate(actual):
                return actual
            time.sleep(0.2)
        observations["autonomous_failure_state"] = actual
        observations["autonomous_failure_status"] = read("SELECT pgreact_api.managed_status()")
        raise AssertionError(description)

    def delivered(before, key):
        actual = wait_for(lambda s: any(r["case_key"] == key and
            r["policy_revision"] == "s1-idle-feasibility" for r in s["requests"]),
            "managed runtime did not autonomously enroll/deliver occurrence " + str(key))
        prior = next(c for c in before["cases"] if c["case_key"] == key)
        expected_cases = copy.deepcopy(before["cases"])
        for case in expected_cases:
            if case["case_key"] == key:
                case.update(escalation_level=2, action_revision=prior["action_revision"] + 1)
        assert actual["cases"] == expected_cases, (actual["cases"], expected_cases)
        assert actual["source"] == before["source"]
        assert actual["selector"] == before["selector"]
        request, = [r for r in actual["requests"] if r["case_key"] == key]
        receipt, = [r for r in actual["receipts"] if r["case_key"] == key]
        attempt, = [a for a in actual["intent_attempts"] if a["case_key"] == key]
        work_ref = request["work_ref"]
        _, episode = work_ref.split(":")[1:]
        activation = read("SELECT to_jsonb(m) FROM pgreact.matches m WHERE name='s1-autonomous' AND semantic_key=" + str(key))
        body = {
            "action": "ESCALATE", "arguments": {"level": 2}, "case_key": key,
            "binding_id": binding["binding_id"], "policy_revision": binding["policy_revision"],
            "expected_policy_digest": binding["policy_digest"][2:],
            "expected_evidence_basis_digest": prior["evidence_basis_digest"][2:],
            "evaluation_ref": "pgreact:" + activation["activation_id"], "work_ref": work_ref,
            **{"expected_" + k: prior[k] for k in ("review_version", "definition_version",
                "publication_revision", "stewardship_epoch", "action_revision")}}
        assert request["request_body"] == body
        key_bytes = "\\x" + sql("SELECT encode(pgreact_mdm.intent_request_key('" +
            binding["binding_id"] + "'::uuid,'s1-idle-feasibility'," + str(key) + ",1," +
            str(prior["action_revision"]) + ",'escalate_level_2',2),'hex')")
        digest = "\\x" + sql("SELECT encode(pgreact_mdm.intent_request_digest('" +
            json.dumps(body).replace("'", "''") + "'::jsonb),'hex')")
        assert request == {
            "binding_id": binding["binding_id"], "request_key": key_bytes,
            "request_digest": digest, "request_body": body, "work_ref": work_ref,
            "policy_revision": binding["policy_revision"], "case_key": key,
            "lifecycle_generation": 1, "action_revision": prior["action_revision"],
            "consequence_identity": "escalate_level_2", "escalation_level": 2,
            "first_episode_id": int(episode), "created_at": request["created_at"]}, request
        assert receipt == {
            "receipt_id": receipt["receipt_id"], "created_at": receipt["created_at"],
            "actor": "pgreact_mdm_worker", "selected_role_name": "pgreact_mdm_worker",
            "session_role_name": "mdm_s1_runtime", "action": "ESCALATE",
            "outcome": "APPLIED_CONTROL", "reason_code": "CONTROL_APPLIED",
            "control": {"assigned_queue": None, "due_at": prior["due_at"].replace("T", " ").removesuffix(":00"),
                        "escalation_level": 2, "manual_assignment_protected": False},
            "case_key": key, "binding_id": binding["binding_id"], "binding_version": binding["binding_version"],
            "action_revision": prior["action_revision"] + 1, "resulting_publication_revision": None,
            "request_body": body, "request_key": key_bytes, "request_digest": digest}, receipt
        assert actual["receipts"] == before["receipts"] + [receipt]
        assert actual["requests"] == sorted(before["requests"] + [request], key=lambda r: r["work_ref"])
        assert attempt == {
            "episode_id": int(episode), "attempt_no": 1, "binding_id": binding["binding_id"],
            "request_key": key_bytes, "request_digest": digest, "request_body": body,
            "work_ref": work_ref, "receipt_id": receipt["receipt_id"],
            "outcome": "APPLIED_CONTROL", "reason_code": "CONTROL_APPLIED", "case_key": key,
            "action_revision": prior["action_revision"] + 1, "control": receipt["control"],
            "resulting_publication_revision": None, "attempted_at": attempt["attempted_at"]}, attempt
        assert actual["intent_attempts"] == before["intent_attempts"] + [attempt]
        work, = [w for w in actual["work"] if w["work_id"] == episode]
        assert work == {"work_id": episode, "kind": "rule", "name": "s1-autonomous", "version": "1",
                        "state": "COMPLETED", "claimable": False, "updated_at": work["updated_at"]}
        core_attempt, = [a for a in actual["attempts"] if a["episode_id"] == int(episode)]
        assert core_attempt == {**{k: core_attempt[k] for k in
            ("execution_id", "started_at", "finished_at", "worker_id")}, "episode_id": int(episode),
            "attempt_no": 1, "status": "COMPLETED", "error_message": None, "error_code": None,
            "event_kind": "ACTIVATE", "name": "s1-autonomous"}
        assert actual["work"] == before["work"] + [work]
        assert actual["attempts"] == before["attempts"] + [core_attempt]
        inspection = read("SET SESSION AUTHORIZATION s1_inspector; SELECT to_jsonb(d) "
            "FROM pgreact_mdm.delivery_inspection_v1 d WHERE work_ref='" + work_ref + "'; RESET SESSION AUTHORIZATION")
        assert inspection == {
            "work_ref": work_ref, "binding_id": binding["binding_id"], "binding_version": binding["binding_version"],
            "entity_name": "policy_qualification", "policy_revision": binding["policy_revision"],
            "policy_digest": binding["policy_digest"][2:], "case_key": key, "lifecycle_generation": 1,
            "action_revision": prior["action_revision"], "action": "ESCALATE", "requested_at": request["created_at"],
            "delivery_outcome": "APPLIED_CONTROL", "delivery_reason_code": "CONTROL_APPLIED",
            "attempted_at": attempt["attempted_at"], "mdm_receipt_id": receipt["receipt_id"],
            "mdm_outcome": "APPLIED_CONTROL", "mdm_reason_code": "CONTROL_APPLIED",
            "resulting_publication_revision": None, "current_case_status": "open",
            "current_publication_revision": prior["publication_revision"], "remediation_state": "NONE",
            "remediation_reason_code": None, "remediation_at": None, "requested_due_at": None,
            "current_due_at": prior["due_at"], "requested_escalation_level": 2, "applied_escalation_level": 2,
            "current_escalation_level": 2, "current_manual_assignment_protected": False,
            "current_pending_stewardship": False}, inspection
        history = read("SET SESSION AUTHORIZATION s1_inspector; "
            "SELECT pgreact_api.deadline_history('s1-autonomous'); RESET SESSION AUTHORIZATION")
        assert history == {"contract_version": 2, "rule_name": "s1-autonomous", "events": history["events"]}
        event, = [e for e in history["events"]
                  if e["semantic_key"] == key and e["event_kind"] == "ACTIVATE"]
        assert event == {"rule_name": "s1-autonomous", "semantic_key": key, "generation": 1,
                         "revision": 0, "event_kind": "ACTIVATE", "declared_deadline": prior["due_at"],
                         "clock_frontier": event["clock_frontier"]}, event
        assert datetime.datetime.fromisoformat(event["clock_frontier"]) >= datetime.datetime.fromisoformat(prior["due_at"])
        assert sql("SELECT has_function_privilege('mdm_s1_runtime',"
                   "'pgreact_mdm.sync_intent_case_identities()','EXECUTE')") == "f"
        assert sql("SELECT has_table_privilege('mdm_s1_runtime','pgtrickle.pgt_dependencies','SELECT')") == "f"
        return actual

    sql("ALTER SYSTEM SET pg_react.databases='s1_idle'", "postgres")
    sql("ALTER SYSTEM SET pg_react.worker_role='mdm_s1_runtime'", "postgres")
    command("docker", "restart", container)
    command("docker", "exec", container, "sh", "-c",
            "until pg_isready -U postgres >/dev/null 2>&1; do sleep 0.2; done")
    first = delivered(before, original)
    observations["autonomous_occurrence_1"] = first
    fixture("autonomous-successor", "/work/tests/integrations/pg-mdm/time/autonomous-successor.sql", "s1_idle")
    prepared = read("SELECT vector FROM s1_auto.before_successor")
    successor, = [c for c in prepared["cases"] if c["issue_key"] ==
        next(c["issue_key"] for c in prepared["cases"] if c["case_key"] == original) and c["occurrence"] == 2]
    assert successor["case_key"] != original and successor["status"] == "open"
    assert not any(i["case_key"] == successor["case_key"] for i in prepared["identities"])
    second = delivered(prepared, successor["case_key"])
    assert [r for r in second["receipts"] if r["case_key"] == original] == [
        r for r in first["receipts"] if r["case_key"] == original]

    def later_cycles():
        started = datetime.datetime.fromisoformat(sql("SELECT clock_timestamp()"))
        wait_for(lambda _: (lambda p: p.get("state") == "ready" and p.get("heartbeat_at") and
            datetime.datetime.fromisoformat(p["heartbeat_at"]) > started + datetime.timedelta(seconds=3))(
                read("SELECT pgreact_api.managed_status()").get("process") or {}),
            "managed cycles failed to advance after recurrence")
        assert state() == second, "later managed cycles changed durable state"

    later_cycles()
    old_postmaster = sql("SELECT pg_postmaster_start_time()")
    command("docker", "restart", container)
    # Wait via docker exec without assuming a fixed startup duration.
    command("docker", "exec", container, "sh", "-c",
            "until pg_isready -U postgres >/dev/null 2>&1; do sleep 0.2; done")
    assert sql("SELECT pg_postmaster_start_time()") > old_postmaster
    later_cycles()
    observations["autonomous_recurrence"] = {"before": prepared, "after": second,
        "exact": True, "old_receipts_unchanged": True, "no_replay_across_cycles_and_restart": True}
    observations["checks"].append({"name": "autonomous-recurrence", "result": "passed"})
    observations["entry_decision"] = "FOCUSED_AUTONOMOUS_RECURRENCE_QUALIFIED"
    print("PASS: autonomous MDM recurrence, exact controls/receipts and cold restart", flush=True)
