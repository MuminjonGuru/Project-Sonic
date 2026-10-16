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
- The first contracts/case increment is described in `docs/agent-artifact-contracts.md`.
  New `agents.models` records and `schemas/agent-v1` do not replace existing finding/run schemas.
  The student approved the two finite conditions (tool parameter to eval; MCP root declaration)
  and development case categories, not independent labels or a final benchmark. Keep these
  authored cases out of held-out data; native mapping and CLI adapter execution remain pending.

### Input/parser follow-up: 2026-10-02

The second library increment implements bounded input validation, conservative policy refusal
and Agent Audit 0.20.0 native parsing/normalization; see `docs/agent-input-parser.md`. The earlier
contracts-only statement above describes its own increment, not the current parser status.
Do not bypass policy blockers or treat parsing as admission/coverage. No public intake worker,
integrated CLI runner or agent reporting path exists yet. Unknown per-file coverage stays unknown;
suppressed findings stay in evidence. Run untrusted AST/JSON parsing inside a bounded worker,
not directly on the host. The library guards do not themselves provide process isolation.

### Bounded runner follow-up: 2 October 2026

The authored-case runner, CLI and reporting path now exist; see `docs/agent-static-runner.md`.
The preceding no-runner statements describe earlier increments. The only admitted inputs for
`scan agent-audit` are the thirteen registered development case IDs, never arbitrary repository
paths. Use the pinned, offline validation worker before native execution. Policy refusal remains
mandatory; no host AST parsing, target imports, config neutralization or model calls.
Native aggregate counts do not establish per-file completion: admitted agent runs remain partial.
Unknown/unexecuted counts remain null in agent details. Preserve native suppressed records as
unreviewed evidence. Agent-containing common reports use v2; legacy-only reports stay v1.
Agent runs use `agent-run-semantic-v1`; existing static runs keep `run-semantic-v2`.
Public source intake, exact-case adjudication, image distribution and wider research profiles
remain separate gates. Do not treat this integration as completion of the 60-point checkpoint.

### Image recovery follow-up: 2 October 2026

PR #6 is merged at `4d310165a4a91d0df8053b5bff460c636f6142d9`. Private exact-image transfer
is described in `docs/agent-image-reproduction.md`. Preserve the OCI index identities and the
original tool configuration. Transfer is not a source rebuild or new admission. Never commit
image archives, private receipts or raw upstream evidence. Independent-machine reproduction and
public distribution clearance remain open; verify controlled cases separately after recovery.

### Artifact inventory follow-up: 2 October 2026

The student confirmed full pinned-revision inventory with separately approved per-tool views.
The first implementation is metadata-only; see `docs/repository-artifact-inventory.md`. Preserve
all supplied entries including tests/examples/docs/CI and unclassified files. Filename candidates
are not parsed artifacts, confirmed framework support, vulnerabilities or scanner admission.
Memory/identity recognition remains unknown. This derivative validates metadata consistency, not
Git-tree completeness or content on disk. The existing public pilot remains dependency-only.
Do not silently expand the catalog or change legacy snapshot/run schemas to connect this layer.

### Git verification and selection follow-up: 2 October 2026

The offline library and authored walkthrough are in `docs/pinned-git-input-plans.md`.
Reconstruct commit/tree/blob identities before binding the full inventory; replay loaded receipts
against retained raw evidence and actual bytes. The user confirmed refusal of symlinks,
submodules and Git LFS pointers, not silent omission or resolution. Record a selected/excluded
decision and reason for every file in each per-tool plan. An exclusion does not bypass full-context
policy/suppression checks; plans confer no execution permission. Public acquisition, selected-view
materialization and research scanner profiles remain gated. Do not retrospectively upgrade the
legacy public dependency archive receipt or change historical evidence hashes.

### Selected-view follow-up: 2 October 2026

PR #9 is merged at `fe6b64dee769cec2d5fed10da6157e4e4c528bce`. The next local increment is
described in `docs/verified-input-views.md`: exact-byte selected views plus the existing isolated
Python/MCP syntax worker, exercised only with four fixed controlled cases. Earlier no-view
statements describe their own increments. Replay full parent evidence before and after validation;
check policy filenames against the full inventory, never only the mounted subset. Selected-input
suppression checks remain mandatory. Do not parse untrusted Python/MCP content on the host.
`input_gate_passed` is not scanner admission, treatment approval, coverage or a security verdict.
New derivative schemas live in `schemas/repository-view-v1/`; legacy contracts remain unchanged.
No public acquisition, arbitrary-path CLI or new security scan is authorized by this bridge.

### Cached source preparation follow-up: 5 October 2026

The bounded cached-evidence path is in `docs/pinned-source-preparation.md`. It verifies the
fixed pilot's commit/tree/blob identities and binds all regular source files to a new inventory.
This is preparation, not new acquisition, author/origin authentication, a security scan or
source-scanning admission. Preserve the old dependency admission and archive receipts unchanged.
The student confirmed Dockerfile remains inventoried but unsupported by the first KICS profile.
Use fresh output directories and retain failures. Do not fetch replacements for mismatched
cached inputs or infer tool coverage from filename candidates. Research profiles, isolated
input/policy validation and source admission still precede same-repository scanner execution.

### Research Semgrep contract follow-up: 5 October 2026

The student approved all 68 pinned GitLab Python rules as the candidate and a research view
plus repository-policy view (Phase 03 P3-D-2026-10-05-07). The first implementation is in
[docs/semgrep-research-contracts.md](docs/semgrep-research-contracts.md): separate versioned
contracts, paired native reconciliation, controlled cases and an offline verification helper.
There is no new public-source CLI or common-report integration. Legacy contracts stay unchanged.

Retain all native suppressions as unreviewed evidence; never synthesize accepted status. Keep
file exclusions separate from size/internal skips and missing evidence. Semgrep can list a file
as both scanned and affected by an error; preserve findings with `reported-with-native-issue`.
The controlled unmatched-rule marker produces exit 2 even with `--disable-nosem`. Verification
of that expected warning is not successful complete analysis. Loaded derivatives require native
replay; scope models do not prove Git acquisition or grant scanner permission. Candidate rules
and private native reports are not redistributed by this increment. No public profile is frozen.

### Guarded research bridge follow-up: 5 October 2026

The user confirmed implicit Git ignore filtering stays disabled in both research views.
The policy view means Semgrep ignore files and inline suppressions only, not project CI.
The additive bridge is described in [docs/guarded-research-runner.md](docs/guarded-research-runner.md).
Use full-parent Git replay, safe local policy includes, exact-byte mounted views and the pinned
syntax worker before the controlled scanner. Missing/escaping/recursive includes are explicit
refusals; do not silently rewrite them or implement host glob matching. An explicit local
`:include .gitignore` is retained as Semgrep policy, not implicit Git exclusion discovery.
Keep process failures and native incomplete analysis distinct. No public-source CLI or common
report integration is granted by this increment; legacy Agent Audit guards remain unchanged.

### Retained research reporting follow-up: 6 October 2026

The additive [offline reporting path](docs/research-common-reporting.md) now accepts one case
directory under a sealed controlled matrix. Earlier no-reporting statements describe their
own increments. Verify the whole seal and replay the selected case's full Git/input/policy,
syntax-response, native and process evidence; do not launch tools during reporting.
Research-containing reports use v3; agent-only combinations stay v2 and legacy-only stay v1.
Keep views/repetitions separate, null unrun counts, explicit synthetic refusal notifications
and native suppression without approval inference. Do not silently broaden this into public
source admission or arbitrary failed-attempt ingestion. Preserve original reports and older
derivatives. Recorded commands/hashes establish consistency, not external attestation.

### Fixed public-source pilot follow-up: 6 October 2026

Phase 03 P3-D-2026-10-06-02 records student approval of the bounded treatment in
[docs/same-repository-pilot.md](docs/same-repository-pilot.md). Earlier dependency-only and
no-public-runner statements describe their respective increments, not this new approval.
The only public source target is the fixed revision in `source-pilot.json`: all 26 Python
files, unchanged 68-rule candidate in two policy views, pinned Agent Audit, and existing
paired dependency paths, repeated three times. No arbitrary-directory CLI or broader
admission. Candidate component metadata remains historical; the outer plan grants finite use.

Do not execute target code, refresh pins, install dependencies, infer MCP from LangGraph,
or add Dockerfile coverage. Preserve unknown framework/per-file analysis and unrun counts.
Use a new attempt directory after failure, never silent retries. The dedicated pilot report
must not masquerade as a controlled-source v3 common report. Retained hashes and replay
establish consistency, not a public vulnerability oracle, independent labels or attestation.

### Public pilot reporting follow-up: 7 October 2026

The additive [public-pilot reporter](docs/public-pilot-reporting.md) now replays completed
sealed pilot evidence into a distinct `public-source-pilot` source and `common-report-v4`.
The earlier separate-envelope instruction remains true for original evidence; do not relabel
the public source as controlled v3 evidence. Preserve three repetitions, both Semgrep views,
all native finding identities and dependency-path separation. Syft remains an inventory row,
not an extra vulnerability SARIF run. No new scanner execution or target admission follows.

Build replays original evidence; standalone derivative validation does not. Known empty
dependency runtime directories are compatible with the retained reader, not permission for
unmanifested content. Keep public findings unreviewed and completeness unknown. Read-model
plan metadata is not the fixed executable admission model. UI, adjudication, benchmark
governance and release rehearsal remain separate work.

### Benchmark-plan follow-up: 13 October 2026

The first [MP-04 plan increment](docs/benchmark-plans.md) validates only the existing authored
Python/MCP case registry and its exact admission/configuration pins. It inventories all source
Python bytes and binds case expectations without executing or materializing target code.
`benchmark validate` and `benchmark dry-run` are offline; a valid plan is not runtime readiness,
permission to launch scanners, implemented resume/scoring or final protocol freeze. Preserve
development family/split identities and explicit malformed/refusal cases. New treatments require
separate admission; do not turn this contract into an arbitrary-path scanning shortcut.

The student clarified that UI and final delivery follow completed development/testing/refinement
and demonstrated usefulness of results. Keep native/historical rules and outcomes unchanged;
refinements need separate versioned treatments and development tests, not tuning held-out cases.
Publication remains local until the student requests otherwise. Report plan position, measured
verification and the next step after each increment.

### Bounded attempt/resume follow-up: 13 October 2026

The [attempt runner](docs/benchmark-attempts.md) reuses the existing authored Agent Audit runner
only. `benchmark run` writes a frozen development plan and unique start/finish records beneath
`workspace/benchmarks/`; `status` replays retained evidence. Do not bypass its shared writer
lock or reuse a status flag without native/bundle/configuration/input/source verification.
Partial analysis and genuine input refusal can finish workflow attempts, never complete security
analysis. Missing Docker, malformed output, diagnostics and unconfirmed cleanup remain failures.
Interrupted/failed attempts block; no retry or automatic repair is implemented. Preserve them.
Current previews use dry-run-v2; v1 plan/preview schema bytes and historical receipts remain intact.
This adds no public/held-out admission, scoring, independent outcome approval or UI readiness.

### Explicit pre-launch retry follow-up: 13 October 2026

Opt-in `benchmark-plan-v2` freezes one manual retry per cell for the exact verified
missing-Docker-before-launch failure. The preparation helper requires `--allow-prelaunch-retry`;
default v1 plans remain no-retry. `benchmark retry` requires the selected failed attempt ID,
fixed cause and remediation assertion. It replays all history under the shared lock and writes
a new linked attempt; it never repairs or overwrites the original. Ordinary `run` never retries.

V2 progress preserves all attempts as well as latest cell states. Do not report only the
successful replacement or treat a partial result as complete. Interruptions, unknown cleanup,
malformed native output, other execution failures and policy refusals are ineligible. No source
changes can be smuggled into recovery: a changed implementation requires a distinct new plan.
V2 plan/start/progress and dry-run-v3 are additive; historical schemas/receipts remain intact.
Other producer handlers, scoring, controlled full rehearsal and usefulness review remain open.
Keep changes local; UI and final delivery remain last. No new target or detector admission.

### Controlled Semgrep governance follow-up: 14 October 2026

The additive [Semgrep handler](docs/benchmark-semgrep.md) admits only the existing original
`dev-semgrep-basic-v1` fixture, unchanged eval rule/profile/tool and one to three repetitions.
It shares the attempt state machine/lock, but uses separate plan/preview/finish/progress contracts;
agent retry policy does not extend to Semgrep. Replay native mappings, exports, configuration,
invocation and retained target bytes before reuse. Workflow completion with/without findings is
not complete security analysis, oracle agreement or safety. Null unparsed results stay null.
Do not broaden this into research-profile/public intake or new rule admission. Interrupted
Semgrep execution requests named-container cleanup but remains blocked without verified evidence.
Old schemas and bundles remain intact. Keep this increment local; UI and final delivery stay last.

### Controlled KICS governance follow-up: 14 October 2026

The additive [KICS handler](docs/benchmark-kics.md) admits only the four existing G2 fixtures,
unchanged pinned v2.1.20 image/profile/two Terraform-Kubernetes queries and one to three sequential
repetitions. Reuse the existing pipeline and shared attempt state machine, with distinct KICS
plan/preview/finish/progress schemas; historical schemas remain unchanged. No retry is admitted.
Replay snapshot, invocation, native JSON mapping, comparison SARIF, exports and semantic evidence
before reuse. Expose native aggregate counters without inferring per-file analysis completeness.
`unsupported` and `partial-analysis` can finish workflow cells but are not clean results or true
negatives. Null unparsed counts remain null. Requests for exception cleanup do not prove cleanup;
failed/interrupted attempts stay blocked. No public Dockerfile support or new research admission.
Keep this development increment local until separately requested; UI and final delivery stay last.

### Controlled dependency governance follow-up: 14 October 2026

The [paired dependency handler](docs/benchmark-dependencies.md) governs only the existing basic
and corrected fixtures, one to three repetitions, through the shared runner. Preserve the
single direct-OSV/Syft/SBOM-OSV pair per attempt, frozen PyPI database and explicit shared config.
No target execution, database refresh, mutation admission, per-stage recovery or retry. Retained
replay requires the original database and host path bindings. Package/match counters remain per
stage, never a summed vulnerability total. Native reports and original bundles stay unchanged.
Failed/unverified attempts block, including interrupted attempts after a cleanup request. Other
dependency cases, research/pilot governance, scoring and usefulness remain open. Keep this
increment local until publication is separately requested; UI and final delivery stay last.

## Safety Controls (All Treatments)


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
