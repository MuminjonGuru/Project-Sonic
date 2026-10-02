# agentsec-evidence

`agentsec-evidence` is a CLI-first research platform for orchestrating security tools,
preserving native evidence, producing provenance-aware normalized records, exporting SARIF,
and measuring evidence quality for AI-agent repositories.

## Current Scope

The current implementation is a working CLI prototype, not a complete agent-security product.
It integrates established scanners and evaluates how their evidence is preserved, compared,
and reported. It does not implement a replacement SAST engine.

| Area | Implemented capability | Evidence boundary |
|---|---|---|
| Code | Pinned Semgrep execution, normalization and SARIF | Project-authored development fixtures |
| Infrastructure-as-Code | Pinned KICS execution, normalization and SARIF | Selected Terraform/Kubernetes queries and authored fixtures |
| Dependencies | Direct OSV analysis compared with Syft -> CycloneDX -> OSV | Controlled PyPI cases and one pinned public-repository lockfile |
| Agent artifacts | Bounded validation worker -> pinned Agent Audit -> normalized evidence and SARIF | Thirteen authored Python/MCP cases only; public source intake gated |
| Common reporting | Validated static/dependency/agent evidence in common JSON and SARIF | Offline derivatives; no new scans or combined vulnerability total |

The static evidence path is:

```text
project-authored fixture
  -> pinned Semgrep or KICS container
  -> write-once, hash-verified native evidence
  -> offline normalization
  -> SARIF 2.1.0
  -> evidence-quality summary
```

The dependency path compares two treatments of the same pinned root lockfile:

```text
uv.lock -> OSV ------------------------------------> direct evidence
uv.lock -> Syft -> native JSON + CycloneDX -> OSV ---> SBOM-path evidence
retained evidence -> validation -> common JSON / SARIF
```

Both OSV treatments use explicit shared settings and the same frozen offline database.
The public pilot is lockfile-only: it does not execute the agent, install dependencies, or
establish runtime exploitability. A successful no-finding scan is not proof of safety.

The first agreed agent-specific integration scope is Python tool definitions and MCP JSON
configurations. The [bounded agent CLI and reporting path](docs/agent-static-runner.md) now
connects the [artifact contracts](docs/agent-artifact-contracts.md) and
[input guards/native parser](docs/agent-input-parser.md) to isolated execution. It refuses
unhandled policy, malformed and unsupported inputs before scanning. Native per-file completion
is not observable, so admitted runs remain explicitly partial, including zero-finding runs.
This path requires two pinned local images; fresh-checkout image distribution remains open.
Prompts/instructions, skills, memory and other agent properties remain broader inventory/later
check work, not implemented coverage. The local UI and held-out evaluation are also pending.

### Evidence Walkthrough

Existing finalized bundles can be inspected, validated and summarized without rerunning a
scanner. Common reporting can combine their evidence into a new derivative while keeping
source labels, statuses, limitations and the two dependency paths separate. See the
[reporting commands and counting rules](docs/common-reporting.md) and
[dependency reproduction and limitations](docs/dependency-pilot.md).

Saved results must be identified as retained evidence, not presented as a live scan. Runtime
workspaces and generated outputs are not distributed in Git, so a fresh checkout does not
include the private pilot bundles or meeting reports.

## Development Environment

- CPython 3.13.15
- uv 0.12.6
- Docker Desktop with Linux containers for scanner execution
- Native Windows/PowerShell CLI development

The documented uv baseline above is unchanged. The 2 October Windows refresh used installed
uv 0.12.13: the frozen lock and installed-dependency checks passed without changing application
dependencies. This observed host-version drift is recorded in the [preflight receipt](docs/agent-audit-preflight.md).

```powershell
uv sync --frozen --all-groups
uv run agentsec-evidence doctor --strict
uv run ruff check .
uv run mypy src tests
uv run pytest
```

The global Python environment is unsupported. Scanner containers receive read-only target
mounts, no Docker socket or host credentials, and denied networking in the static profile.

## Development Runs

From this repository in PowerShell:

```powershell
uv run agentsec-evidence scan semgrep `
  .\test_cases\development\semgrep-basic\target `
  --label fixture:semgrep-basic `
  --revision fixture-v1 `
  --source-kind project-fixture `
  --license-status project-authored-private
```

Run the pinned KICS development treatment:

```powershell
uv run agentsec-evidence scan kics `
  .\test_cases\development\kics-basic\target `
  --label fixture:kics-basic `
  --revision fixture-v1 `
  --source-kind project-fixture `
  --license-status project-authored-private
```

Findings do not make `scan` fail. System outcomes use separate exit codes: `0` complete,
`8` partial, `4` execution/timeout, `5` parse/validation, and `6` safety refusal.

Finalized data can be processed without invoking the producer again:

```powershell
uv run agentsec-evidence inspect <run-id> --json
uv run agentsec-evidence validate <run-id> --json
uv run agentsec-evidence summarize <run-id> --json
uv run agentsec-evidence normalize <run-id> --output .\outputs\normalization
uv run agentsec-evidence export sarif <run-id> --output .\outputs\results.sarif
```

Offline derivatives must be written outside the finalized run bundle.

## Evidence Flow

```text
source directory
  -> deterministic snapshot and inventory
  -> trusted Docker argv plan
  -> pinned scanner image (network none; target read-only)
  -> bounded stdout, stderr, native JSON, and optional native comparison output
  -> exact-byte content-addressed blob store
  -> strict offline parser
  -> finding, coverage, and failure JSONL
  -> deterministic SARIF export
  -> schema, provenance, SARIF, and bundle validation
  -> finalized manifest
```

One successful run contains:

```text
run.json                         events.jsonl
target/snapshot.json             target/inventory.jsonl
executions/<id>/execution.json   executions/<id>/stdout.bin
executions/<id>/stderr.bin       executions/<id>/inputs/*
executions/<id>/native/*         executions/<id>/parser-report.json
executions/<id>/blobs.json
normalized/findings.jsonl        normalized/coverage.jsonl
normalized/failures.jsonl        exports/results.sarif
exports/summary.json             validation/{schema,sarif,provenance}.json
bundle-manifest.json
```

Raw, normalized, and export products are classified `internal` by default. A future public
release operation must perform an explicit allowlist/redaction step; a valid bundle is not a
public-safe bundle.

## Repeatability Semantics

`run-semantic-v2` compares stable target, tool, configuration, parser-accounting, normalized,
failure, coverage, and SARIF semantics. It excludes opaque run/record IDs, timestamps, runtime
duration, and exact raw-blob locator hashes. Producer-native outputs may include timing and
runtime metadata, so exact native hashes can differ across otherwise equivalent runs. Those
bytes and hashes remain preserved and independently validated in every bundle.

The first real three-run fixture check produced one native and normalized finding per run,
zero failures, complete provenance, valid OASIS SARIF, and one identical semantic SHA-256 across
all three runs. This verifies evidence handling repeatability only; it is not a detection claim.

The KICS treatment pins image digest, source revision, built-in query-pack inventory hash,
platforms, query IDs, parser controls, and output formats in `configs/tools/kics.toml`. The
native JSON is canonical; native KICS SARIF is retained only as a comparison artifact. A zero
finding result is distinct from an unsupported target or a partial parse.

## Dependency Evidence Pilot (2026-09-18)

The separately versioned `dependencies run` and `dependencies validate` commands now compare
direct root `uv.lock` -> OSV with one Syft discovery -> native JSON plus external CycloneDX ->
OSV. Both OSV paths use the same explicit configuration and frozen offline PyPI database.
See [dependency reproduction and limitations](docs/dependency-pilot.md).

The finite controlled scope was explicitly reviewed by the student. The public pilot uses
`langchain-samples/cicd-pipeline-example` at `5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf`:
159 eligible PyPI identities across all lockfile markers/groups, with the editable root counted
separately. This is an admitted formative example, not the final benchmark corpus or a deployed
runtime. No dependencies, target tests, builds or agents are executed. No paid service or hosted
model is required. No findings remains a valid result, not a reason to replace this case.

Package name/version projection retention is reported separately from lost source qualifiers;
occurrences and native relationships are retained but their full fidelity is not scored.
Reported package appearance does not prove successful per-package vulnerability matching.
Dependency evidence now participates in offline common reporting, with a separately versioned
package summary and two SARIF runs for the direct and SBOM paths. Existing file-based contracts
are unchanged. See [common reporting](docs/common-reporting.md) for commands and counting rules.
The GUI, full G2 gate and coverage of all AI-agent artifacts remain open.

The dependency decision/protocol records live in the sibling `Project_Phase_02` planning
folder; active integration planning continues in `Project_Phase_03`. Neither planning folder
is distributed in this development checkout. `AGENTS.md` and `docs/` summarize the relevant
implementation guardrails. Existing supported commands and result contracts are unchanged.

Shared code lives in `src/agentsec_evidence/orchestration/shared.py`; producer planning/parsing
stays separate. `tools/verify_orchestration_regression.ps1` runs and validates the five existing
Docker fixtures and can compare against a saved baseline. Use a fresh directory under
`workspace` for its `-ReportDirectory` argument. The pinned Ubuntu verification build is in
`containers/verification/`. These checks establish engineering compatibility, not detection
accuracy or confirmatory benchmark readiness.

## Repository Boundary

All implementation, tests, fixtures, benchmark definitions, runtime workspaces, and generated
outputs live under this repository. Planning and decision history remains in the sibling
`Project_Phase_02` and `Project_Phase_03` folders. Runtime workspaces and generated outputs
remain ignored; execution evidence is not automatically committed with implementation changes.

## Publication Status

The source-license and university intellectual-property decision is not yet resolved. This is
currently a private research implementation; no permission to redistribute the source is
granted by the absence of a license file.
