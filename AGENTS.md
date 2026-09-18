# Development Repository Instructions

## Boundary

This repository contains implementation and execution artifacts. Planning decisions, mentor
notes, and academic provenance remain in `../Project_Phase_02/` and must not be rewritten from
here. Development commits and release hashes may be referenced there.

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

## Safety

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
