# Bounded Development Attempts and Resume

This MP-04 increment executes **only** the existing, fixed authored Python/MCP Agent Audit
treatment. It reuses `orchestration.agent_pipeline`, not a second scanner implementation.
It adds no repository, detector, profile, database or target-execution admission. Scoring,
additional producer handlers, interrupted-run recovery and final-study freeze remain
separate work. The UI follows useful reviewed results, not merely a runnable command.

## Commands

Prepare an explicit development plan using [the plan helper](benchmark-plans.md). Plans bind
the current source bytes: a code change requires a new development plan, not overwriting a
prior receipt. For a freshly prepared `workspace/example/plan.json`:

```powershell
uv run --frozen --offline --no-sync agentsec-evidence benchmark validate workspace/example/plan.json
uv run --frozen --offline --no-sync agentsec-evidence benchmark dry-run workspace/example/plan.json
uv run --frozen --offline --no-sync agentsec-evidence benchmark run workspace/example/plan.json --max-new-cells 1
uv run --frozen --offline --no-sync agentsec-evidence benchmark status workspace/example/plan.json
uv run --frozen --offline --no-sync agentsec-evidence benchmark run workspace/example/plan.json
```

`validate`, `dry-run` and `status` launch no tools. `run` is explicit execution of the existing
admitted development treatment. Docker readiness is checked by the existing runner, not inferred
from a valid plan. Missing Docker is a failed attempt, not an input-policy refusal.

`--max-new-cells` deliberately pauses **between** cells. Repeating `run` verifies and skips
eligible terminal attempts before continuing unattempted cells. It never retries a failed,
interrupted, timed-out, malformed-output or evidence-invalid attempt. These block ordinary
continuation. The separate opt-in pre-launch retry command below is the only retry exception.
CLI exit 5 indicates a blocked workflow or invalid evidence; normal interruption propagates.
Exit 0 means the bounded command finished without a blocking error, **not** clean analysis, and
can describe an intentional between-cell pause (`workflow_complete=false`).

## Explicit Pre-Launch Retry

Prepare the plan with `tools/prepare_development_benchmark.py --allow-prelaunch-retry` to freeze
the v2 policy **before the first attempt**. This permits one manual retry per cell, not a retry
until the desired security outcome appears. `run` never performs this retry automatically.

After restoring Docker command availability, use the exact failed attempt ID from `status`:

```powershell
uv run --frozen --offline --no-sync agentsec-evidence benchmark retry workspace/example/plan.json --attempt-id attempt_<recorded-id> --cause docker-unavailable-before-launch --remediation docker-command-availability-restored
```

The command checks the current source/plan bindings, obtains the same exclusive writer lock,
replays the entire history and revalidates the failed bundle. Eligibility requires the exact
known missing-tool failure together with no validation/scanner launch evidence, unchanged
inputs, unparsed/null native counts and the expected pre-launch admission state. A count of
zero scanner calls alone is insufficient: the input-validation container must not have run
either. Docker command availability is checked before consuming the retry, but daemon/image
readiness is not inferred from that check. A later launch error consumes the one retry and stops.

The explicit request records the selected prior attempt, fixed cause and remediation assertion
in a new start record that also binds the previous finish hash. This does not authenticate the
operator or prove their remediation claim; the new attempt must supply its own verified result.
No free-text exception, username or secret is added to the portable authorization record.
The command executes **one replacement attempt only**, leaving subsequent cells for `run`.

`benchmark-progress-v2` includes both latest-per-cell `cells` and the complete ordered `attempts`
ledger. `newly_attempted_cells` excludes a retry; `newly_created_attempts` includes it. Do not
calculate failure rates or execution cost from latest cells alone. A recovered cell does not
erase the original failure. Preparation, repair and review effort are not measured by the gap
between attempt timestamps and must not be reported as human-work time.
Here, `manual_retry_attempts` means explicitly requested through the separate command rather
than automatically scheduled by `run`; the command may itself be scripted. It is not a count
of authenticated human interventions.

Legacy v1 plans have no retry permission. No migration, automatic retry, hard-kill repair,
container-orphan inference, malformed-output retry, refusal retry or evidence repair is provided.
Changing code requires a new plan; it is not remediation within an existing frozen session.

## Write-Once History

All execution material is beneath the development repository:

```text
workspace/benchmarks/
  .writer.lock
  <semantic-plan-sha256>/
    plan.json
    validation.json
    attempts/
      0001_attempt_<uuid>/
        start.json
        execution/             existing runner workspace: bundles, inputs, snapshots
        finish.json
      0002_attempt_<uuid>/...
```

The shared OS-held lock prevents concurrent writers through this benchmark entry point in the
same checkout. It is left on disk intentionally; process exit releases the OS lock. Do not delete
it to bypass an active writer. Other existing scan commands and other checkouts do not share this
lock; the operator must still obey the project's sequential resource policy.

Start and finish records are exclusive-create, flushed writes, never replaced. Each finish binds
its start hash; each subsequent start binds the previous finish hash. Case order, repetition,
cell identity and plan bytes are checked. V1 plans allow one attempt per cell; opt-in v2 plans
allow a first attempt and at most one authorized pre-launch retry. Duplicate attempt/run IDs,
skipped cells and unlinked or ineligible retries are rejected. Filesystem ownership can still alter
or delete these files: write-once application behavior is not WORM storage or authenticated
attestation. A torn record or incomplete initialization is retained and refused, not repaired.

Before reuse, the platform validates bundle integrity, schema, SARIF, native normalization and
semantic projection, and checks the exact case inventory, selected paths, source registry,
worker-source identities, profile, rules and image identities against the plan. It compares the
whole retained bundle file inventory with the finish record. Links, hard links, unexpected files,
extra run bundles and unsafe execution IDs are refused. It rechecks source/plan pins before each
dispatch and afterward. These checks assume no hostile concurrent administrator modifying the
checkout; they do not attest the loaded interpreter or authenticate a scanner's claims.

## Outcome Vocabulary

| Cell state | Interpretation | Resume treatment |
|---|---|---|
| `not-attempted` | No start record | Eligible for a first attempt |
| `partial-analysis` | Valid native observations; per-file completeness remains unknown | Revalidate, then skip this terminal attempt |
| `refused` | Completed input validation refused scanner admission | Revalidate, retain reasons, then skip; not a true negative |
| `execution-failed` | Infrastructure, parsing, diagnostics, cleanup or verification failure | Stop; only the frozen, explicit pre-launch exception can create a retry |
| `interrupted` | Keyboard interruption or start without a finish | Stop; no implicit relaunch or recovery |

The first treatment cannot emit `analysis_complete=true`. A zero stored finding count in a
partial run is not a demonstrated absence of the condition. For refused/unparsed cases, the
finding count remains null. Diagnostic/cleanup failures do not become reusable merely because
some native findings exist. `workflow_complete` describes terminal eligible **attempts**, not
complete security coverage. Refused and partial rows stay visible in progress output.

For a caught exception, the history uses a fixed error category rather than leaking exception
text. Retained execution files may contain additional diagnostic evidence but are not claimed
verified if verification failed. A hard kill can leave a container; this increment does not
automatically infer orphan cleanup or restart it. Inspect retained run/container identities and
resolve cleanup explicitly before a future, separately recorded recovery. Ordinary cancellation
reaps the host subprocess and the existing agent runner attempts named-container cleanup.

## Contract Versions and Limits

The [controlled Semgrep handler](benchmark-semgrep.md) reuses this state machine and writer lock
with separate plan/finish/progress contracts. It admits only the original three-file fixture,
with no retry. The agent-specific versions and bounds below retain their original scope.
The [controlled KICS handler](benchmark-kics.md) also shares the runner and lock, using distinct
plan/finish/progress contracts for four existing fixtures. Its reusable `unsupported` state is
not successful security analysis. KICS has no retry permission and no new Dockerfile treatment.

- `benchmark-plan-v1` and the historical `benchmark-dry-run-v1` schema remain unchanged.
- New previews use [benchmark-dry-run-v2](../schemas/benchmark-v2/dry-run.schema.json), accurately
  describing bounded terminal-attempt resume while retaining `execution_authorized=false` and
  unchecked runtime readiness for the preview operation itself.
- Additive records are [attempt start](../schemas/benchmark-v1/attempt-start.schema.json),
  [attempt finish](../schemas/benchmark-v1/attempt-finish.schema.json) and
  [progress](../schemas/benchmark-v1/progress.schema.json).
- Opt-in recovery adds [plan v2](../schemas/benchmark-v2/plan.schema.json),
  [start v2](../schemas/benchmark-v2/attempt-start.schema.json),
  [progress v2](../schemas/benchmark-v2/progress.schema.json) and
  [preview v3](../schemas/benchmark-v3/dry-run.schema.json); finish v1 remains unchanged.
- At most 13 admitted cases, 3 repetitions, 39 cells, 78 attempts with explicit v2 recovery,
  one writer and no automatic retry. V1 sessions remain capped at 39 attempts.
- Native scanner and syntax-worker limits remain the existing 2 CPU / 2 GiB, offline,
  read-only, non-root container treatment. Target code is not imported or installed.
- Replay guards bound bundle entries, depth, individual bytes and total bytes; attempt JSON
  records have a 2 MiB limit. Retained snapshots and scratch are not substitutes for sealed
  native evidence. Preserve all older evidence; do not reseal it with current hashes.

Tests use authored process doubles for governance assertions, plus a separate bounded real
Docker rehearsal. Neither is a held-out detection benchmark or independent outcome review.
