# Governed Fixed Public Pilot

This additive MP-04 handler runs the existing admitted source pilot through the shared
benchmark attempt ledger. It does not admit another repository or replace the pilot runner.

## Execution Unit

One benchmark cell is the **whole fixed pilot**, containing three sequential repetitions of
both Semgrep views, Agent Audit and the direct/SBOM dependency paths. The 18 stage rows stay
separate. Three syntax-worker invocations are separate from 18 scanner invocations.
The outer repetition is one; inner repetitions are not independent repositories.

Reuse requires full retained replay. There is no per-stage resume or retry for this treatment.
A failed/interrupted attempt blocks its session, retaining the original evidence. A fresh plan
is a separate attempt, not recovery of the previous one. Missing/failed evidence has null
aggregate counters, never a clean result. Finished workflow remains `partial-analysis`:
static per-file completeness is unknown.

## Bound Inputs

The wrapper freezes the existing source-pilot admission, configs and validation schemas,
all implementation Python bytes, three cached Git/archive resources, the unchanged 68 rule
files and license, and the original PyPI database. Paths are workspace-relative. Validation
checks bytes without scanning, fetching or installing the target. Source materialization
and full Git/object validation remain the existing pilot's input gate.

The only target remains `langchain-samples/cicd-pipeline-example` at
`5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf`. Both Semgrep views disable implicit Git filtering.
Dockerfile remains unsupported; `langgraph.json` is not MCP. No input, rule or version refresh.

## Commands

Prepare the existing resources described in [the pilot contract](same-repository-pilot.md).
The new output parent must already exist under the ignored workspace.

```powershell
uv run python tools/prepare_pilot_benchmark.py `
  --plan-id source-pilot-governed-v1 `
  --cache workspace/dependency-pilot-intake-2026-09-18 `
  --rule-source workspace/phase3-semgrep-broad-assessment-2026-10-05/upstream-full-01/source `
  --database workspace/dependency-preflight-2026-09-18/database/osv-scanner/PyPI/all.zip `
  --output workspace/my-pilot-plan.json
uv run agentsec-evidence benchmark validate workspace/my-pilot-plan.json
uv run agentsec-evidence benchmark dry-run workspace/my-pilot-plan.json
uv run agentsec-evidence benchmark run workspace/my-pilot-plan.json
uv run agentsec-evidence benchmark status workspace/my-pilot-plan.json
```

The commands use the shared writer lock/history verification. Repeated `run` on a verified
finished session launches nothing. Blocked sessions return the established nonzero CLI result.
Native failures stay beneath `execution/pilot`, outside completed-pilot reporting admission.

## Evidence and Limits

New schemas: `schemas/benchmark-public-pilot-v1/`; historical contracts stay unchanged.
Replay checks frozen resources/source, native evidence seal, exact invocations and ordered
rows through existing public reporting. No heterogeneous vulnerability total or accuracy score.
Hashes establish consistency, not external attestation. Original host paths and frozen
resources are required; this is not independent-machine reproduction.

The existing public-pilot common-report reader accepts the retained completed evidence.
Controlled research-case governance, MP-04 acceptance, offline scoring, independent outcome
review and useful-results acceptance remain separate work. UI and final delivery stay last.
