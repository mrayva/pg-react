"""Deterministic claimed React delivery versus authorized MDM pause."""
import copy
import json
import subprocess
import time


def qualify(sql, command, fixture, container, observations):
    fixture("claimed-work-setup", "/work/tests/integrations/pg-mdm/time/claimed-work.sql", "s1_idle")
    read = lambda query: json.loads(sql(query))
    state = lambda: read("SELECT s1_claimed.state()")
    worker = "claimed-pause-regression"
    binding = read("SELECT to_jsonb(b) FROM pgreact_mdm.policy_intent_bindings b WHERE enabled")
    runtime = read("SELECT runtime_version FROM pgreact_mdm.policy_intent_runtime")
    before = state()
    assert before["receipts"] == before["requests"] == before["intent_attempts"] == []
    claim = read("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
        "SELECT to_jsonb(c) FROM pgreact_api.claim('" + worker + "',1,interval '60 seconds') c")
    key = claim["bindings"]["case_key"]
    episode = int(claim["episode_id"])
    processes = []

    def start(name, query, interactive=False):
        args = ["docker", "exec"] + (["-i"] if interactive else []) + [container,
            "psql", "-XAtq", "-U", "postgres", "-d", "s1_idle", "-v", "ON_ERROR_STOP=1"]
        prefix = "SET application_name='" + name + "'; SET statement_timeout='30s'; "
        process = subprocess.Popen(args + ([] if interactive else ["-c", prefix + query]),
            stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if interactive:
            process.stdin.write(prefix + query + "\n")
            process.stdin.flush()
        processes.append(process)
        return process

    def wait_for(predicate, label):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            result = predicate()
            if result:
                return result
            time.sleep(0.05)
        raise AssertionError(label)

    def activity(name):
        return read("SELECT COALESCE((SELECT jsonb_build_object('pid',pid,'state',state,"
            "'blockers',pg_blocking_pids(pid)) FROM pg_stat_activity WHERE application_name='" + name + "'),'null')")

    def finish(process):
        out, error = process.communicate(timeout=35)
        assert process.returncode == 0, (out, error)
        return out.strip()

    def operator(function, version):
        return read("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT pgreact_mdm." + function + "('" + binding["binding_id"] + "'::uuid," + str(version) + ")")

    def claim_one():
        return read("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
            "SELECT COALESCE(jsonb_agg(to_jsonb(c)),'[]') FROM pgreact_api.claim('" + worker + "',1,interval '60 seconds') c")

    def execute(c):
        return read("SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
            "SELECT to_jsonb(pgreact_api.execute(" + str(c["episode_id"]) + ",'" + worker + "','" + c["lease_token"] + "'::uuid))")

    def check_delivery(prior, actual, c, outcome, reason, generation=1, current_case=None):
        case_key = c["bindings"]["case_key"]
        case = next(x for x in prior["cases"] if x["case_key"] == case_key)
        current_case = current_case or case
        expected_cases = copy.deepcopy(prior["cases"])
        for row in expected_cases:
            if row["case_key"] == case_key:
                row.update(current_case)
                if outcome == "APPLIED_CONTROL":
                    row.update(escalation_level=2,action_revision=case["action_revision"]+1)
        assert actual["cases"] == expected_cases, (expected_cases,actual["cases"])
        ref = "pgreact:" + c["rule_version_id"] + ":" + str(c["episode_id"])
        body = {"action":"ESCALATE","arguments":{"level":2},"case_key":case_key,
            "binding_id":binding["binding_id"],"policy_revision":binding["policy_revision"],
            "expected_policy_digest":binding["policy_digest"][2:],
            "expected_evidence_basis_digest":case["evidence_basis_digest"][2:],
            "evaluation_ref":"pgreact:"+c["activation_id"],"work_ref":ref,
            **{"expected_"+k:case[k] for k in ("action_revision","review_version","definition_version","publication_revision","stewardship_epoch")}}
        request, = [r for r in actual["requests"] if r["work_ref"] == ref]
        digest = "\\x"+sql("SELECT encode(pgreact_mdm.intent_request_digest('"+json.dumps(body).replace("'","''")+"'::jsonb),'hex')")
        request_key = "\\x"+sql("SELECT encode(pgreact_mdm.intent_request_key('"+binding["binding_id"]+
            "'::uuid,'s1-idle-feasibility',"+str(case_key)+","+str(generation)+","+str(case["action_revision"])+",'escalate_level_2',2),'hex')")
        assert request == {"binding_id":binding["binding_id"],"request_key":request_key,"request_digest":digest,
            "request_body":body,"work_ref":ref,"policy_revision":binding["policy_revision"],"case_key":case_key,
            "lifecycle_generation":generation,"action_revision":case["action_revision"],"consequence_identity":"escalate_level_2",
            "escalation_level":2,"first_episode_id":int(c["episode_id"]),"created_at":request["created_at"]},request
        receipt, = [r for r in actual["receipts"] if r["request_body"]["work_ref"] == ref]
        revision = current_case["action_revision"] + (outcome == "APPLIED_CONTROL")
        control = {"assigned_queue":None,"due_at":current_case["due_at"].replace("T"," ").removesuffix(":00"),
            "escalation_level":2 if outcome == "APPLIED_CONTROL" else current_case["escalation_level"],"manual_assignment_protected":False}
        assert receipt == {"receipt_id":receipt["receipt_id"],"created_at":receipt["created_at"],"actor":"pgreact_mdm_worker",
            "selected_role_name":"pgreact_mdm_worker","session_role_name":"mdm_s1_runtime","action":"ESCALATE",
            "outcome":outcome,"reason_code":reason,"control":control,"case_key":case_key,"binding_id":binding["binding_id"],
            "binding_version":binding["binding_version"],"action_revision":revision,"resulting_publication_revision":None,
            "request_body":body,"request_key":request_key,"request_digest":digest},receipt
        attempt, = [a for a in actual["intent_attempts"] if a["work_ref"] == ref]
        assert attempt == {"episode_id":int(c["episode_id"]),"attempt_no":1,"binding_id":binding["binding_id"],
            "request_key":request_key,"request_digest":digest,"request_body":body,"work_ref":ref,"receipt_id":receipt["receipt_id"],
            "outcome":outcome,"reason_code":reason,"case_key":case_key,"action_revision":revision,"control":control,
            "resulting_publication_revision":None,"attempted_at":attempt["attempted_at"]},attempt
        assert actual["requests"] == sorted(prior["requests"]+[request],key=lambda r:r["work_ref"])
        assert actual["receipts"] == prior["receipts"]+[receipt]
        assert actual["intent_attempts"] == prior["intent_attempts"]+[attempt]
        for name in ("source","technical_source"):
            assert actual[name] == prior[name]
        work, = [w for w in actual["work"] if w["work_id"] == str(c["episode_id"])]
        assert work == {"work_id":str(c["episode_id"]),"kind":"rule","name":"s1-claimed-work","version":"1",
            "state":"COMPLETED","claimable":False,"updated_at":work["updated_at"]},work
        core, = [a for a in actual["attempts"] if a["episode_id"] == int(c["episode_id"])]
        assert core == {**{k:core[k] for k in ("execution_id","started_at","finished_at")},"episode_id":int(c["episode_id"]),
            "worker_id":worker,"attempt_no":1,"status":"COMPLETED","error_message":None,"error_code":None,
            "event_kind":"ACTIVATE","name":"s1-claimed-work"},core

    try:
        holder = start("claimed-case-holder", "BEGIN; SELECT case_key FROM mdm_steward.policy_cases_v1 "
                       "WHERE case_key=" + str(key) + " FOR UPDATE;", interactive=True)
        held = wait_for(lambda: (lambda a: a if a and a["state"] == "idle in transaction" else None)(
            activity("claimed-case-holder")), "case holder did not acquire its row lock")
        delivery = start("claimed-delivery", "SET SESSION AUTHORIZATION mdm_s1_runtime; "
            "SET ROLE pgreact_mdm_worker; SELECT to_jsonb(pgreact_api.execute(" + str(episode) +
            ",'" + worker + "','" + claim["lease_token"] + "'::uuid))")
        blocked = wait_for(lambda: (lambda a: a if a and held["pid"] in a["blockers"] else None)(
            activity("claimed-delivery")), "React delivery did not reach the MDM case lock")
        pause = start("claimed-pause", "SET SESSION AUTHORIZATION mdm_legacy_login; "
            "SET ROLE mdm_legacy_administrator; SELECT pgreact_mdm.pause_intent_binding('" +
            binding["binding_id"] + "'::uuid," + str(runtime) + ")")
        barrier = wait_for(lambda: "acknowledged" if pause.poll() is not None else (
            (lambda a: a if a and blocked["pid"] in a["blockers"] else None)(activity("claimed-pause"))),
            "pause neither acknowledged nor waited for the in-flight delivery")
        acknowledged_early = barrier == "acknowledged"
        during = state()
        holder.stdin.write("COMMIT;\n\\q\n")
        holder.stdin.flush()
        finish(holder)
        delivered = json.loads(finish(delivery))
        paused_version = int(finish(pause))
        after = state()
        observations["claimed_pause"] = {"claim": claim, "holder": held, "delivery": blocked,
            "pause_barrier": barrier, "pause_acknowledged_before_delivery_release": acknowledged_early,
            "runtime_before": runtime, "runtime_after": paused_version, "before": before,
            "during": during, "after": after, "delivery_result": delivered}
        applied = [r for r in after["receipts"] if r["case_key"] == key and r["outcome"] == "APPLIED_CONTROL"]
        assert not (acknowledged_early and applied), "authorized pause acknowledged before a blocked React delivery subsequently applied ESCALATE"
        assert not acknowledged_early, "pause did not serialize with the in-flight delivery"
        assert delivered == "COMPLETED"
        assert paused_version == runtime + 1
        check_delivery(before,after,claim,"APPLIED_CONTROL","CONTROL_APPLIED")

        # Pause owns the binding first. Delivery must read runtime again after
        # its lock wait, rather than use an eligibility snapshot from before it.
        active_version = operator("reconcile_intent_binding",paused_version)
        before_b = state()
        claim_b, = claim_one()
        pause_first = start("claimed-pause-first","BEGIN; SET SESSION AUTHORIZATION mdm_legacy_login; "
            "SET ROLE mdm_legacy_administrator; SELECT pgreact_mdm.pause_intent_binding('"+
            binding["binding_id"]+"'::uuid,"+str(active_version)+");",interactive=True)
        paused = wait_for(lambda:(lambda a:a if a and a["state"]=="idle in transaction" else None)(
            activity("claimed-pause-first")),"pause did not finish its uncommitted transition")
        delivery_b = start("claimed-delivery-b","SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
            "SELECT to_jsonb(pgreact_api.execute("+str(claim_b["episode_id"])+",'"+worker+"','"+claim_b["lease_token"]+"'::uuid))")
        blocked_b = wait_for(lambda:(lambda a:a if a and paused["pid"] in a["blockers"] else None)(
            activity("claimed-delivery-b")),"delivery did not wait behind the pause binding lock")
        pause_first.stdin.write("COMMIT;\n\\q\n")
        pause_first.stdin.flush()
        paused_b_version = int(finish(pause_first))
        assert json.loads(finish(delivery_b)) == "COMPLETED"
        after_b = state()
        observations["pause_first_delivery"] = {"claim":claim_b,"blocked":blocked_b,"before":before_b,"after":after_b}
        check_delivery(before_b,after_b,claim_b,"BINDING_PAUSED","BINDING_PAUSED")

        # A fully committed pause precedes the next claim. Keep the old queued
        # identity, but submit no MDM request from the now-ineligible episode.
        sql("SELECT pgreact_api.run()")
        active_version = operator("reconcile_intent_binding",paused_b_version)
        sql("SELECT pgreact_api.run()")
        committed_version = operator("pause_intent_binding",active_version)
        before_committed = state()
        for _ in before["cases"]:
            c, = claim_one()
            assert execute(c) == "COMPLETED"
        assert claim_one() == []
        after_committed = state()
        for name in ("cases","receipts","requests","intent_attempts","holds","source","technical_source"):
            assert after_committed[name] == before_committed[name],name
        observations["pause_committed_before_claim"] = {"before":before_committed,"after":after_committed}

        # Fresh reevaluation after authorized resumption may progress the case
        # whose previous attempted request ended terminally paused.
        sql("SELECT pgreact_api.run()")
        active_version = operator("reconcile_intent_binding",committed_version)
        sql("SELECT pgreact_api.run()")
        before_fresh = state()
        for _ in before["cases"]:
            c, = claim_one()
            assert execute(c) == "COMPLETED"
            if c["bindings"]["case_key"] == claim_b["bindings"]["case_key"]:
                fresh = state()
                observations["fresh_after_pause"] = {"before":before_fresh,"after":fresh}
                check_delivery(before_fresh,fresh,c,"APPLIED_CONTROL","CONTROL_APPLIED",generation=3)
        assert claim_one() == []
        after_fresh = state()
        observations["fresh_after_pause"] = {"before":before_fresh,"after":after_fresh}
        assert after_fresh["receipts"][:len(after_b["receipts"])] == after_b["receipts"]
        paused_ref = "pgreact:"+claim_b["rule_version_id"]+":"+str(claim_b["episode_id"])
        inspections = read("SET SESSION AUTHORIZATION s1_claimed_reader; SELECT jsonb_agg(jsonb_build_object('work_ref',work_ref,'outcome',delivery_outcome,"
            "'remediation',remediation_state,'reason',remediation_reason_code) ORDER BY requested_at) "
            "FROM pgreact_mdm.delivery_inspection_v1 WHERE case_key="+str(claim_b["bindings"]["case_key"]))
        assert inspections == [{"work_ref":paused_ref,"outcome":"BINDING_PAUSED","remediation":"HELD","reason":"BINDING_PAUSED"},
            {"work_ref":after_fresh["receipts"][-1]["request_body"]["work_ref"],"outcome":"APPLIED_CONTROL","remediation":"NONE","reason":None}],inspections

        # A human lowering the already-applied level cannot authorize it again,
        # even after a fresh React generation produces a different request key.
        for current in after_fresh["cases"]:
            sql("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
                "SELECT mdm_steward.set_case_controls("+str(current["case_key"])+",NULL,'"+current["due_at"]+"'::timestamptz,1,false,"+
                str(current["action_revision"])+",'Claimed-work cross-key human reduction')")
        paused_version = operator("pause_intent_binding",active_version)
        sql("SELECT pgreact_api.run()")
        active_version = operator("reconcile_intent_binding",paused_version)
        sql("SELECT pgreact_api.run()")
        before_lowered = state()

        # React claims first, then an authorized human changes its deadline and
        # commits while delivery is waiting on that human-held case lock.
        edit_claim, = claim_one()
        key = edit_claim["bindings"]["case_key"]
        old_case = next(c for c in before_lowered["cases"] if c["case_key"]==key)
        future = read("SELECT to_jsonb(clock_timestamp()+interval '1 hour')")
        human = start("claimed-human-edit","BEGIN; SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT action_revision FROM mdm_steward.set_case_controls("+str(key)+",NULL,'"+future+"'::timestamptz,1,false,"+
            str(old_case["action_revision"])+",'Claimed-work human deadline replacement');",interactive=True)
        human_lock = wait_for(lambda:(lambda a:a if a and a["state"]=="idle in transaction" else None)(
            activity("claimed-human-edit")),"human edit did not hold its case row")
        edit_delivery = start("claimed-edit-delivery","SET SESSION AUTHORIZATION mdm_s1_runtime; SET ROLE pgreact_mdm_worker; "
            "SELECT to_jsonb(pgreact_api.execute("+str(edit_claim["episode_id"])+",'"+worker+"','"+edit_claim["lease_token"]+"'::uuid))")
        edit_wait = wait_for(lambda:(lambda a:a if a and human_lock["pid"] in a["blockers"] else None)(
            activity("claimed-edit-delivery")),"React delivery did not wait for the human edit")
        human.stdin.write("COMMIT;\n\\q\n")
        human.stdin.flush()
        edited_revision = int(finish(human))
        assert edited_revision == old_case["action_revision"]+1
        assert json.loads(finish(edit_delivery)) == "COMPLETED"
        edited_case = {**old_case,"due_at":future,"action_revision":edited_revision}
        stale_edit = state()
        observations["human_edit_after_claim"] = {"claim":edit_claim,"barrier":edit_wait,"before":before_lowered,"after":stale_edit}
        check_delivery(before_lowered,stale_edit,edit_claim,"STALE_CASE","FRESHNESS_TOKEN_MISMATCH",generation=4,current_case=edited_case)

        # The second human change commits before React even claims its old
        # episode. The native callback must recheck eligibility and do nothing.
        second_key = next(c["case_key"] for c in before_lowered["cases"] if c["case_key"]!=key)
        second = next(c for c in stale_edit["cases"] if c["case_key"]==second_key)
        sql("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT mdm_steward.set_case_controls("+str(second_key)+",NULL,'"+second["due_at"]+"'::timestamptz,2,false,"+
            str(second["action_revision"])+",'Human level change before claim')")
        before_edit_first = state()
        edit_first_claim, = claim_one()
        assert edit_first_claim["bindings"]["case_key"] == second_key
        assert execute(edit_first_claim) == "COMPLETED"
        after_edit_first = state()
        for name in ("cases","receipts","requests","intent_attempts","holds","source","technical_source"):
            assert after_edit_first[name] == before_edit_first[name],name
        observations["human_edit_before_claim"] = {"before":before_edit_first,"after":after_edit_first}

        sql("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT mdm_steward.set_case_controls("+str(key)+",NULL,'"+old_case["due_at"]+"'::timestamptz,1,false,"+
            str(edited_revision)+",'Authorized due-time restoration after stale request')")
        paused_version = operator("pause_intent_binding",active_version)
        sql("SELECT pgreact_api.run()")
        active_version = operator("reconcile_intent_binding",paused_version)
        sql("SELECT pgreact_api.run()")
        before_lowered = state()
        for _ in before["cases"]:
            c, = claim_one()
            assert execute(c) == "COMPLETED"
            if c["bindings"]["case_key"] == key:
                check_delivery(before_lowered,state(),c,"ACTION_DENIED","ESCALATION_LEVEL_ALREADY_APPLIED",generation=5)
        assert claim_one() == []
        terminal = state()
        for _ in range(3):
            assert read("SET SESSION AUTHORIZATION mdm_s1_runtime; SELECT pgreact_api.managed_cycle()")["state"] == "ready"
        assert state() == terminal,"later managed cycles changed terminal vectors"
        observations["cross_key_after_human_reduction"] = {"before":before_lowered,"after":terminal}

        # A replacement lowers the binding limit after one claim, but before
        # either delivery. Previously eligible queued work cannot use old caps.
        second = next(c for c in terminal["cases"] if c["case_key"]==second_key)
        sql("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT mdm_steward.set_case_controls("+str(second_key)+",NULL,'"+second["due_at"]+"'::timestamptz,1,false,"+
            str(second["action_revision"])+",'Replacement barrier setup')")
        paused_version = operator("pause_intent_binding",active_version)
        sql("SELECT pgreact_api.run()")
        operator("reconcile_intent_binding",paused_version)
        sql("SELECT pgreact_api.run()")
        old_claim, = claim_one()
        replacement = read("SET SESSION AUTHORIZATION mdm_legacy_login; SET ROLE mdm_legacy_administrator; "
            "SELECT to_jsonb(b) FROM pgreact_mdm.replace_intent_binding('"+binding["binding_id"]+"'::uuid,"+
            str(binding["binding_version"])+",'s1-idle-feasibility',ARRAY['ESCALATE'],ARRAY[]::text[],NULL,1) b")
        before_replaced = state()
        assert execute(old_claim) == "COMPLETED"
        new_claim, = claim_one()
        assert execute(new_claim) == "COMPLETED"
        assert claim_one() == []
        replaced = state()
        for name in ("cases","receipts","requests","intent_attempts","holds","source","technical_source"):
            assert replaced[name] == before_replaced[name],name
        old_binding = read("SELECT to_jsonb(b) FROM pgreact_mdm.policy_intent_bindings b WHERE binding_id='"+binding["binding_id"]+"'::uuid")
        assert old_binding == {**binding,"enabled":False},old_binding
        new_binding = read("SELECT to_jsonb(b) FROM pgreact_mdm.policy_intent_bindings b WHERE binding_id='"+replacement["binding_id"]+"'::uuid")
        assert new_binding == {**binding,**replacement,"max_escalation_level":1,"created_at":new_binding["created_at"]},new_binding
        observations["replacement_claim_orders"] = {"claimed_before":old_claim,"claimed_after":new_claim,
            "old_binding":old_binding,"new_binding":new_binding,"before":before_replaced,"after":replaced}
        for _ in range(3):
            assert read("SET SESSION AUTHORIZATION mdm_s1_runtime; SELECT pgreact_api.managed_cycle()")["state"] == "ready"
        assert state() == replaced,"managed cycles ignored replacement or replayed old work"
        observations["entry_decision"] = "FOCUSED_CLAIMED_PAUSE_QUALIFIED"
        observations["checks"].extend({"name":name,"result":"passed"} for name in (
            "claimed-pause-barrier","pause-first-runtime-freshness","paused-before-claim",
            "human-edit-claim-orders","binding-replacement-claim-orders",
            "fresh-after-terminal-pause","cross-key-after-human-reduction"))
        print("PASS: claimed-work pause/edit/replacement matrix, fresh resumption and cross-key uniqueness", flush=True)
    finally:
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name IN "
            "('claimed-case-holder','claimed-delivery','claimed-pause','claimed-pause-first','claimed-delivery-b','claimed-human-edit','claimed-edit-delivery') AND pid<>pg_backend_pid()")
        for process in processes:
            if process.poll() is None:
                process.communicate(timeout=35)
