# Bounded Benchmark Plans

The first MP-04 increment adds an offline plan validator and dry run. It supports only the
existing thirteen authored Python/MCP development cases and their pinned Agent Audit treatment.
It is not a general benchmark runner, public-repository admission or final-study freeze.

The subsequent [attempt/resume increment](benchmark-attempts.md) adds serial execution for
this same finite treatment. Validation/dry-run remain non-executing; broader producers,
scoring, interrupted-run recovery and final-study governance remain separate. Explicit
pre-launch infrastructure retry is opt-in through the additive v2 plan described below.

The [controlled Semgrep handler](benchmark-semgrep.md) adds its own exact first-slice plan and
preview contracts. The agent-specific admission details below still apply only to agent plans.

## Commands

Prepare a new plan after the implementation changes for an increment are finished. The helper
requires an existing private workspace directory and refuses an existing output file or a
destination inside finalized evidence. Case flags give an explicit order; repeats are bounded
to one through three and remain engineering repetitions, not independent samples.

```powershell
uv run python tools/prepare_development_benchmark.py --plan-id agent-controls-v1 --case python-positive --case python-corrected --case python-near-miss --case mcp-positive --output workspace/agent-controls-plan.json
uv run agentsec-evidence benchmark validate workspace/agent-controls-plan.json
uv run agentsec-evidence benchmark dry-run workspace/agent-controls-plan.json
```

Both CLI commands validate the same complete bindings. `validate` emits a compact JSON summary;
`dry-run` emits the ordered cells, authored expectations, prospective stages and declared resource
limits. Semantic plan and cell identities are deterministic. The raw plan-file hash separately
detects byte changes such as reformatting. CLI exit 5 means validation failed; Typer argument
errors retain its usual exit behavior. No scanner or Docker availability is required.

### Optional Pre-Launch Recovery Policy

The preparation helper defaults to the unchanged `benchmark-plan-v1` no-retry contract.
Pass `--allow-prelaunch-retry` **before execution** to create a `benchmark-plan-v2` with the
frozen `missing-docker-prelaunch-once-v1` policy. It allows one explicit manual retry per cell
only when verified retained evidence shows Docker was unavailable before either container
launched. Automatic retries stay zero. Interrupted runs, other failures and policy refusals
remain ineligible. See [the retry command and evidence conditions](benchmark-attempts.md).

V2 plans emit `benchmark-dry-run-v3` previews. Existing plan/preview schemas are not rewritten
to gain this capability. A prior failed v1 session cannot be migrated, re-pinned or silently
restarted through this feature. New plans are distinct development rehearsals, not replacements
for old results; a confirmatory-study retry policy remains a separate freeze decision.

## Bound Inputs

- Exact six-file admission: case registry, tool config, execution profile, property registry,
  `pyproject.toml` and `uv.lock`. Known approved hashes live in the service's narrow admission
  table. Editing and re-hashing a protected file in a supplied plan does not grant admission.
- Every `src/**/*.py` file in the supplied project tree is bound by path, size and hash. Missing,
  added or changed Python source invalidates an existing plan. This is declared project-source
  identity, not attestation of the running interpreter or installed environment.
- Each case binds the full authored file inventory, including policy context, plus the separate
  selected scanner input. The validator compares these bytes' hashes with the existing registry;
  it never materializes, imports, executes or host-parses target Python ASTs.
- Expected parse state, observable condition and policy observation come from the authored
  registry, not native findings. Their provenance is student-approved case categories, not
  independent review of the exact text. Refused/malformed cases remain planned, not clean.
- Every case remains in the `agent-artifact-development-v1` family and development split.
  Arbitrary cases, family relabeling, public/pilot/held-out roles and final-freeze assertions are
  rejected. This prevents relabeling this family; it is not general fork/near-duplicate detection.
- Explicit case order, repeat count, sequential-only execution design and no automatic retries.
  Metric names are design identifiers for future scoring, not evidence of implemented metrics.

The plan contract is [benchmark-plan-v1](../schemas/benchmark-v1/plan.schema.json). The historical
[benchmark-dry-run-v1](../schemas/benchmark-v1/dry-run.schema.json) remains unchanged; current
previews use [benchmark-dry-run-v2](../schemas/benchmark-v2/dry-run.schema.json) to describe the
implemented finite resume scope without claiming execution or readiness. Earlier scan, reporting,
research and review contracts are unchanged. Generate schemas with
`uv run python tools/generate_benchmark_schemas.py`.

## Security and Failure Boundaries

Plan JSON is bounded to 2 MiB and rejects duplicate keys. References use canonical relative
paths, finite counts and byte budgets. File reads reject symlinks, reparse points and hard links.
The code inventory checks directories before descending and caps depth, entries and total bytes.
Protected inputs are rechecked before returning. These are point-in-time consistency checks,
not a concurrency lock or permission to execute later without revalidation.

No subprocess, network, target parser or scanner is invoked by validation/dry-run. Plans cannot
carry arbitrary shell commands, image replacements, permissive resource settings or new input
directories. CLI tests explicitly fail if a subprocess or network socket is attempted.

The result deliberately states:

- `plan_valid: true`, **not** successful analysis.
- `execution_authorized: false`; a metadata receipt cannot bypass existing runner admissions.
- `runtime_readiness: not-checked`; image availability/integrity, dependencies and host resources
  need execution preflight later. No database is part of this agent-only treatment.
- Every cell is `not-attempted`, with zero producer invocations, null finding counts and
  unmeasured coverage. Authored expectations are not observed parser/refusal outcomes.
- Bounded terminal-attempt resume is implemented separately; each preview names its exact scope. Scoring
  is not implemented. The dry-run is not a completed experiment or scanner authorization.

## What Comes Next

MP-04 now has [write-once attempt history, compatible-result reuse, failure/interruption
handling and concurrency guards](benchmark-attempts.md) for this development treatment. It
reuses the existing agent runner. Opt-in v2 plans permit one explicitly requested, verified
missing-Docker pre-launch retry; interrupted and other failed attempts still stop without
relaunch. Public-pilot and other producer
treatments need explicit additional plan handlers; their existing direct runners are unchanged.

MP-05 supplies offline scoring and denominator/unknown handling, followed by repeated development
rehearsal and evidence-quality review. UI implementation starts only after development, testing
and any justified versioned rule/profile refinement demonstrate useful, explainable results.
Final delivery/reproduction follows that stage. Neither a date nor a passing plan validator is
the UI-readiness gate; no guarantee of exhaustive or flawless security findings is implied.

Published upstream rules and historical profiles are not silently edited. A changed treatment
needs its own pins, rationale, admission and development checks; final held-out cases cannot be
used to tune it. Paid tools and new public repositories are not prerequisites for this increment.
