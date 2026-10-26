# pg-mdm stewardship adapter

The v0.47 package is a read-only policy layer over the approved
`MDM-STEWARDSHIP/1` projection. It validates an authorized case relation,
publishes immutable React-owned policy revisions, and exposes deterministic
routing, elapsed-time deadline, and fixed-population comparison reads. The
additive v0.48 worker package submits reviewed queue, due-date, and escalation
intents through pg-react's existing episode transaction.

The v0.47 read path never writes an MDM relation, calls `submit_policy_intent`,
creates React work, advances a lifecycle frontier, or invokes a refresh. The
v0.48 worker writes only through `mdm_steward.submit_policy_intent`; MDM remains
the authority for each action. Live v0.47 qualification passed against pg-mdm
v0.13.1 (extension version 0.14.0), which provides
`mdm_steward.policy_cases_v1`; fixture qualification uses a separate schema.
Support is limited to the approved 100-case pilot envelope. Production-scale
resource and recovery limits remain unsupported; see the
[v0.48.0 release notes](../../docs/v0.48.0-release-notes.md).

Install the SQL files in order:

```text
integrations/pg-mdm/sql/policy-inputs.sql
integrations/pg-mdm/sql/routing.sql
integrations/pg-mdm/sql/deadline-preview.sql
integrations/pg-mdm/sql/comparison.sql
integrations/pg-mdm/sql/typed-flow.sql
integrations/pg-mdm/sql/request-store.sql
integrations/pg-mdm/sql/intent-worker.sql
```

The public seams are:

- `pgreact_mdm.validate_inputs(source_relation)` and
  `pgreact_mdm.policy_inputs(source_relation)` for the authorized projection.
- `pgreact_mdm.publish_package(policy_revision, package)` for immutable package
  publication and `pgreact_mdm.policy_document(policy_revision)` for review.
- `pgreact_mdm.route_cases(source_relation, policy_revision[, entity_name])`
  for winner, ambiguity, no-candidate, protection, and no-op explanations.
- `pgreact_mdm.route_cases(source_relation, policy_revision, entity_name, captured_at)`
  for the same read at one explicit finite database-time sample (`NULL` entity
  selects all entities). Equality with `due_at` counts as due. The existing
  overloads sample `statement_timestamp()` once; population comparison uses its
  supplied `captured_at` for both routing and deadline proposals. Its
  explanation records that sample, the current deadline and escalation level,
  the requested level, due status, and the specific ineligibility reason.
- `pgreact_mdm.deadline_preview(source_relation, policy_revision, captured_at[, entity_name])`
  for explicit-time deadline proposals.
- `pgreact_mdm.compare_population(...)` for complete or partial bounded
  comparisons with an explicit coverage manifest.

The explicit-time routing read is preparatory work for
[managed bounded escalation #11](https://github.com/trickle-labs/pg-react/issues/11). It does not
register a managed escalation policy or certify delivery. The
[implementation status](../../docs/v0.49-issue-11-status.md) records the
owner-confirmed semantics, satisfied MDM fixture prerequisite, and remaining
managed-runtime gates.

After the core extension is installed, load `typed-flow.sql` and pass the
returned `pgreact_api.declaration` to `pgreact.validate`, `pgreact.preview`,
`pgreact.review_token`, and `pgreact.compare`. The bridge adds the signed MDM
source as a typed policy support relation. The typed version includes the
published package digest, so route or deadline changes require a new revision
and declaration review. It does not deploy or run the declaration.
Run `tests/integrations/pg-mdm/v0.47-typed.sql` after the fixture test in a
database with the core extension installed to check that identity.

For v0.48, publish a canonical intent package with
`pgreact_mdm.publish_intent_package(policy_revision, package)`. Run
`pgreact_mdm.intent_declaration`, review its preview, then deploy it through
`pgreact.deploy` before creating any binding. pg-react checks that the runner
owns the candidate views and callback functions. After installing the adapter,
a DBA grants `pgreact_mdm_worker` to a non-superuser runner login with
`SET TRUE, INHERIT FALSE`, then calls
`pgreact_mdm.configure_intent_deployer(login_role)`. The runner must have no
membership in the MDM helper or entity execution roles. pg-react also needs its
login to read `mdm_steward.policy_cases_v1` when it creates the evaluation stream;
it receives no MDM binding or receipt access. The selected NOLOGIN worker reads
only the authorized case projection. The runner owns the intent views and
callbacks, which invoke the worker-owned submission function. After deploying
the three rules, call `configure_intent_deployer(login_role)` again; this leaves
rule review and refresh owned by the runner and assigns the generated episode
dispatchers to the worker.

After deployment, the entity execution role creates or replaces a binding with
`pgreact_mdm.create_intent_binding` or
`pgreact_mdm.replace_intent_binding`. Grant that role `USAGE` on `pgreact_mdm`
so it can call these adapter routines. Each operation activates or reconciles
the MDM binding and makes its local runtime eligible. The runner then calls
`pgreact_mdm.sync_intent_case_identities()` and refreshes the three rules before
processing episodes. Run `pgreact_mdm.execute_intent_episode` with the runner
session set to `pgreact_mdm_worker`; refresh rules as the runner because pg-react
checks rule ownership. The adapter stores a stable bigint identity for each
entity and case pair because MDM case keys are entity-scoped. Run the sync
before refresh whenever MDM may have new cases. After a restore, the entity
execution role must call
`pgreact_mdm.reconcile_intent_binding(binding_id, 0)` before the runner syncs
identities and refreshes rules. Use `pgreact_mdm.pause_intent_binding` to pause
a live binding.

The worker role is `pgreact_mdm_worker`: `NOLOGIN`, `NOSUPERUSER`,
`NOBYPASSRLS`, and `NOINHERIT`. It can read the authorized case projection and
execute `submit_policy_intent`; it has no direct access to MDM binding or
receipt tables, and no membership path to `mdm_helper_owner` or the entity
execution role. MDM rejects its calls to human decision, refresh, rebuild, and
identity APIs. The adapter helper is owned by `mdm_helper_owner` and restores
only the narrow worker grants after binding creation, replacement, or
reconciliation.

The read-only `pgreact_mdm.delivery_inspection_v1` view reports the current
deadline and escalation level beside the requested level and the level recorded
in an applied MDM receipt. It also carries binding and policy versions,
delivery state, receipt outcome, and remediation reason. The receipt level is
historical; the current case level may change after a later human action.

Run `tests/integrations/pg-mdm/v0.48-codec.sql` after the fixture test, then
run `tests/integrations/pg-mdm/v0.47-live-setup.sql` to create the second MDM
entity used to exercise escalation. Run
`tests/integrations/pg-mdm/v0.48-live.sql` and
`tests/integrations/pg-mdm/v0.48-security.sql` in the joint pg-mdm 0.14 /
pg-react database. The scripts expect the MDM `foundation` E2E setup, including
the non-superuser `mdm_legacy_login` and `mdm_test_login`. The live script
creates a test-only `mdm_m2_runner` login that can set only the worker role;
each entity execution role creates its own binding. Run
`tests/integrations/pg-mdm/v0.48-restore.sh` only in a disposable joint cluster;
it pauses the source binding and recreates the worker role to qualify logical
restore, stale database and role OIDs, and entity-role reconciliation. The
checked-in v0.48 SQL checks passed on the local pg-mdm 0.14.0 image. T48.04-T48.10
and the retention approval remain open. See [the qualification evidence](../../tests/integrations/pg-mdm/evidence/v0.48.0.md)
for the results and remaining gates.
The image carries the matching pg-mdm `configure_helper.sql`; when running the
restore script from a host checkout, set `MDM_HELPER_CONFIG` to that file so
restored MDM helpers regain their protected ownership before reconciliation.

For installed MDM M1 qualification, bootstrap the upstream image with
`/tests/e2e.sql` and `/tests/e2e_policy.sql`, then run
`tests/integrations/pg-mdm/v0.47-live-setup.sql` followed by
`tests/integrations/pg-mdm/v0.47-live.sql` in a disposable joint database.

The package is adapter-owned and optional; the core pg-react extension remains
usable without it.

For the managed-deadline candidate, see the [v0.49 qualification profile and
operator procedure](../../docs/v0.49-qualification.md). It records prospective
limits, focused upgrade/recovery proofs and the remaining release gates.
