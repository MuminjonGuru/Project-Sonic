# Development Repository Instructions

## Boundary

This repository contains implementation and execution artifacts. Phase 02 baseline decisions
remain in `../Project_Phase_02/`; active integration and agent-specific planning continues in
`../Project_Phase_03/` from 2026-10-02. Do not rewrite those planning/provenance records from
implementation work. Development commits and release hashes may be referenced there.

The handoff is recorded in Phase 02 `D-2026-10-02-01` and the Phase 03 execution plan. It
prioritizes development and validation of the useful static core, not all candidate integrations.
Existing tool/case admission gates remain in force; no new baseline, framework or detector is
approved merely by opening Phase 03. Required human intervention is a question to measure.

## Current Development Contract

- CLI/distribution: `agentsec-evidence`
- Python package: `agentsec_evidence`
- Python: 3.13.15 through a committed uv lock
- Host CLI: native Windows or Linux
- Scanner: pinned disposable Docker container
- G1: Semgrep native JSON -> normalized JSONL -> SARIF -> summary
- G2-A: KICS native JSON -> normalized JSONL -> project SARIF -> summary
- KICS native SARIF: retained and checked only as a comparison artifact
- Inputs: authored development fixtures and the explicitly admitted pinned dependency pilot only

G2-A acceptance alone does not authorize later tools or experiments. The separate 2026-09-18
working decision establishes the dependency-analysis direction below. The shared refactor is
implemented and committed at `dd5f668a3fd764314a8886807cd924dc9f438da5`. Dependency adapters,
controlled fixtures and the first pinned pilot are now implemented; see `docs/dependency-pilot.md`.
Vendor tools, dynamic
testing, a UI and custom AI-agent checks retain their separate gates. Do not reinterpret G2-A
or this documentation update as completion of the full G2 adapter layer.

## Next Dependency Stage: 2026-09-18

Planning authority: `../Project_Phase_02/DECISION_REGISTER.md`, decisions D-2026-09-18-01 to -15,
and `../Project_Phase_02/G2_CORE_ADAPTER_LAYER/DEPENDENCY_ANALYSIS_PROTOCOL_2026-09-18.md`.
Those planning files are outside this Git repository; the essential development guardrails are:

- Shared orchestration now lives in the public `orchestration.shared` module. Its September 18
  verification passed 72 tests on Windows and Ubuntu and a five-case before/after/repeat Docker
  matrix with identical semantics. Preserve those contracts; do not reintroduce private
  cross-producer imports or label this as Syft/OSV implementation.
- Add package/occurrence/relationship records; the existing file inventory is not that model.
- Compare direct pinned dependency input -> OSV with one Syft discovery producing native JSON
  and CycloneDX -> OSV. Preserve all native evidence; put generated SBOMs outside the target.
- Use identical explicit OSV config, no baseline suppressions, no call/reachability analysis,
  no remote resolution, strict offline matching and frozen per-ecosystem database hashes.
  Select exact tool/schema versions and verify flags against those builds before the pilot.
- Verify all-package visibility; distinguish reported identity from proven matching completion.
  Preserve aliases, different versions and occurrences; no findings does not mean safe.
- Separate producer exit codes from platform failure status; unsupported/partial/error cannot
  become clean. Preserve backward compatibility or version any schema/semantic changes.
- Author independent single-ecosystem expectations, review them, then automate positive,
  negative and copied-SBOM mutation assertions. Neither Syft nor direct OSV is ground truth.
- Begin with one suitable pinned public pilot only after fixture/admission gates. The preferred
  candidate is `langchain-samples/cicd-pipeline-example` at
`5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf`, admitted in `test_cases/pilot/langgraph-cicd/admission.json`. Record replacement
  reasons; never drop it merely because there are no findings. Keep it out of held-out data.
- D-2026-09-18-15 confirms lockfile-wide PyPI inventory across markers/groups for that first
  pilot, recording the editable project separately. Do not install target dependencies or
  reinterpret the lockfile as one installed runtime. The admitted denominator is 159, plus one local root.
- Keep execution artifacts here, not in phase folders. No target installs/builds/tests/agent
  execution for this static pilot. Paid tooling and hosted models are not prerequisites.
- Measure semantic repeatability and complete paired-path cost, including Syft generation;
  unsupported identities and observability limits remain visible beside metric denominators.

Dependency evidence uses `dependency-bundle-v1` and `dependency-semantic-v2`, separate from
static `run-semantic-v2`. The v2 dependency projection canonicalizes only known unordered Syft
optional extras and their dependency lists. Preserve earlier v1 hashes and raw bundles; never
sort arbitrary sequences to manufacture agreement. OSV 2.6.0 requires its database bind mount
at `/database/osv-scalibr/PyPI/all.zip`; do not follow an unverified moving documentation path.

## Common Reporting: 2026-09-18

`inspect`, `summarize`, `validate` and `export sarif` also accept dependency run IDs. The
`report build` command combines validated static/dependency bundles into a new derivative;
`report validate` verifies it. See `docs/common-reporting.md`.
Keep `common-report-v1` and `dependency-summary-v1` separate from original source contracts.
Never sum paired OSV paths or heterogeneous finding units into one vulnerability total.
Missing evidence is null, not zero. Package SARIF uses logical locations, no fabricated source
lines and no inferred severity. Existing evidence must remain byte-identical. A valid report
does not establish successful analysis, consumer compatibility or public-release clearance.

## Phase 03 Agent Integration: 2026-10-02

Planning authority: Phase 03 decisions P3-D-2026-10-02-05/06 and
`../Project_Phase_03/PREFLIGHT_AND_INTEGRATION_CONTRACT_2026-10-02.md`.
The portable engineering summary is [docs/agent-audit-preflight.md](docs/agent-audit-preflight.md);
the sibling planning files and raw execution workspace are not distributed with this checkout.

- First user-confirmed scope: Python tool definitions and MCP JSON configurations. Skills,
  prompts and memory remain broader inventory/later checks, not current detector coverage.
- Agent Audit 0.20.0 at `8c4c5cb9bddd4758b064577c912ee8afcaf5330f` passed finite container
  feasibility checks, not full adapter or research admission. Receipts and raw bytes are under
  `workspace/phase3-preflight-2026-10-02/`; this is authored engineering data, not held-out evidence.
- Before public source scanning, implement explicit input accounting, parse/error classification,
  trusted policy and suppression handling. Native exit zero and aggregate `scanned_files` do not
  establish complete successful analysis; target-local config can silently exclude files.
- Preserve all native assertions, including overlapping rules and questionable mappings, without
  treating upstream confidence/actionability/risk scores as validated platform measurements.
- Continue via existing producer-neutral orchestration and reporting contracts; preserve old
  bundles. No target execution, live inspection, model calls or target dependency installation.
- Baseline refresh passed 115 Windows tests; no fresh Ubuntu application-suite run in this batch.
  Contracts and reviewed finite expectations precede the integrated adapter and new source pilot.

## Safety Controls

- Build subprocess commands as argument arrays. Never invoke scanner commands through a shell.
- Mount targets read-only; deny scanner networking; never expose the Docker socket or host home.
- Preserve stdout, stderr, and native reports as bytes before parsing.
- Preserve the exact profile, tool configuration, and rule/query selection used by each run.
- Treat malformed, missing, partial, and timed-out output as explicit failures, never as clean.
- Treat unsupported/not-applicable evidence separately from a successful no-finding scan.
- Never commit credentials, raw third-party targets, private evidence, runtime workspaces, or
  generated outputs.
- Keep development, pilot, held-out, and demo cases separate.

## Required Checks

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
```
