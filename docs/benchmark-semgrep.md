# Controlled Semgrep Benchmark Handler

MP-04 admits the original first-slice fixture to the existing serial benchmark runner. This is
evidence-governance work, not a new detector, research profile or target. Agent Audit v1/v2
contracts and their separately limited retry policy remain unchanged.

## Fixed Treatment

- Case: `dev-semgrep-basic-v1`, from [case.toml](../test_cases/development/semgrep-basic/case.toml).
- Three inventoried files: `vulnerable.py`, `clean.py`, `ignored/ignored.py`.
- Intended selection: the first two; `ignored/**` retains the original explicit exclusion.
- Rule: unchanged [authored eval rule](../rules/project-authored/semgrep-first-slice.yml).
  This is not the 68-rule GitLab research treatment or comprehensive agent-security coverage.
- Semgrep 1.174.0, its existing image digest, profile, lockfile and package configuration are pinned.
- One case, one to three sequential engineering repetitions, no automatic or manual retry.
  Repetitions are not independent samples; these inputs cannot be relabeled as held-out.

The historical case expects one native rule record. The plan adds positive/corrected/excluded
path context but does not turn authored expectations into independent adjudication. No scores
are computed here. A zero-result observation remains an observation even when it disagrees with
the expectation; later scoring must expose that disagreement.

## Commands

Use an existing private `workspace` directory and a new filename. Preparation binds every
`src/**/*.py` file, so finish source edits before preparing a plan. A source change invalidates
reuse; do not rewrite a historical session to accept new hashes.

```powershell
uv run python tools/prepare_development_benchmark.py --treatment semgrep-first-slice --plan-id semgrep-controls-v1 --case dev-semgrep-basic-v1 --repetitions 3 --output workspace/semgrep-controls-plan.json
uv run agentsec-evidence benchmark validate workspace/semgrep-controls-plan.json
uv run agentsec-evidence benchmark dry-run workspace/semgrep-controls-plan.json
uv run agentsec-evidence benchmark run workspace/semgrep-controls-plan.json --max-new-cells 1
uv run agentsec-evidence benchmark run workspace/semgrep-controls-plan.json
uv run agentsec-evidence benchmark status workspace/semgrep-controls-plan.json
```

Validation, dry-run and status do not invoke Docker. Run reuses `run_semgrep_scan`, with an
isolated execution directory per attempt. The shared writer lock, frozen session, ordered
start/finish chain and explicit run budget are the same mechanisms as the agent treatment.
CLI exit zero means no blocking workflow error, not complete analysis or a safe target.

## Evidence and Status

Before reuse, verification checks admission and implementation, the exact target, retained
snapshot/inventory, native bundle, config/rule bytes, invocation, resource limits, producer
identity, native normalization/parser counts, SARIF, summary and semantic projection. Stored
target snapshots are also hashed in this treatment's receipt. Finish records must retain their
canonical bytes, including the latest record before a successor exists. Consistency checks
are not authentication against a filesystem owner able to rewrite the entire history.

| Attempt state | Meaning and continuation |
|---|---|
| `completed-with-findings` | Native workflow completed with records; reusable, not validated vulnerabilities |
| `completed-without-findings` | Native workflow completed with zero records; reusable, not proof of safety |
| `partial-analysis` | Parsed native diagnostics under accepted exit policy; reusable but incomplete |
| `execution-failed` | Failed launch/process, rejected version, malformed evidence or verification failure; blocks |
| `interrupted` | Interrupted/unfinished attempt; blocks, no inferred recovery |
| `not-attempted` | No observation; counts remain null |

`scanner_invocations` counts recorded scanner launch attempts, not guaranteed successful analysis.
Missing Docker before launch records zero. Finding count is null without a parsed report; legacy
summary zero defaults are not used as clean-scan evidence. Native path reporting does not prove
per-file completion. `analysis_complete=false` remains explicit even when the workflow completes.

The legacy Semgrep producer now requests named-container cleanup on exceptional exit as well as
its established timeout/output-limit path. An interruption without a verified bundle remains
unverified and blocked; it does not establish proven cleanup or authorize retry.

## Contracts and Limits

Additive contracts: [plan](../schemas/benchmark-semgrep-v1/plan.schema.json),
[preview](../schemas/benchmark-semgrep-v1/dry-run.schema.json),
[finish](../schemas/benchmark-semgrep-v1/attempt-finish.schema.json),
[progress](../schemas/benchmark-semgrep-v1/progress.schema.json).
Start records reuse unchanged `benchmark-attempt-start-v1`. Old schemas/evidence are not migrated.
Small-case replay uses existing bounded read/tree guards, including a 16 MiB per-file replay limit.
No target installation, imports, execution, remote resolution or model calls occur.

Tests cover changed admissions/source/expectations, failure/null states, cancellation cleanup,
locking, byte tampering, paused continuation, reuse and compatibility. Real-container rehearsal
is separately recorded; process doubles are not scanner evaluations.

Next: controlled KICS and dependency handlers, already-admitted research/pilot treatments,
offline scoring and development-only usefulness review. UI and final delivery follow useful,
tested results. This increment does not complete MP-04 or the dissertation.
