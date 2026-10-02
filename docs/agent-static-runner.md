# Bounded Agent-Static Runner

Engineering increment, 2 October 2026. Starts at merged PR #5,
`37757e1f591030f9468a131a579a39c64b69c9aa`. This is authored development integration,
not public-source admission, an independent accuracy study or a new general-purpose detector.

## Scope and Commands

The CLI accepts only the 13 IDs in `test_cases/development/agent-artifacts/cases.json`, not
repository paths. The two student-approved conditions are a Python tool argument passed to
eval and an MCP filesystem-server declaration for `/`. Exact fixture text is not independently
adjudicated. The existing public repository remains admitted for lockfile analysis only.

```powershell
uv run agentsec-evidence scan agent-audit python-positive --json
uv run agentsec-evidence scan agent-audit mcp-positive --json
uv run agentsec-evidence scan agent-audit python-malformed --json
uv run agentsec-evidence inspect <run-id> --json
uv run agentsec-evidence validate <run-id> --json
uv run agentsec-evidence summarize <run-id> --json
uv run agentsec-evidence normalize <run-id> --output .\outputs\new-agent-derivative
uv run agentsec-evidence export sarif <run-id> --output .\outputs\new-agent.sarif
uv run agentsec-evidence report build <bundle-directory> --output .\outputs\new-agent-report
uv run python tools/verify_agent_development.py --output .\workspace\new-agent-matrix
```

CLI exit 8 means partial evidence; 6 means refused admission; 4 means execution failure/timeout;
5 means parse/derived-product failure. Native exit codes remain separate. Offline normalization
requires successfully parsed native evidence. Derivative/matrix destinations must be new.

Both images in `configs/tools/agent-audit.toml` must already exist. They are **local image IDs,
not downloadable registry references**. Preflight source, compatibility lock, wheelhouse and
Dockerfile remain under private `workspace/phase3-preflight-2026-10-02/`; the validator uses
the existing locked regression image. Fresh-checkout image preparation/distribution and
dependency-license clearance remain open. The later [private image recovery helper](agent-image-reproduction.md)
can export and verify/import the exact existing image IDs without rebuilding them. This is not
public distribution or an independent-machine/source-build reproduction claim. No helper downloads images, refreshes rules,
installs target dependencies or invokes a model.

## Invocation Flow

```text
registered authored case -> new materialized view -> immutable hashed snapshot
  -> bounded validation container: inventory/hash checks, AST or strict JSON parsing
  -> response binding to exact request -> conservative policy gate
       refused -> retained input/status/diagnostics -> finalized rejected bundle
       admitted -> offline Agent Audit container -> raw streams + stage receipt
                -> strict native parser -> normalized observations + assessments
                -> SARIF + summary -> schema/provenance validation -> sealed bundle
  -> offline inspect / normalize / common reporting (no scanner rerun)
```

`orchestration/agent_pipeline.py` coordinates stages using producer-neutral `orchestration.shared`.
`agents/worker.py` parses inside Docker; `agents/inputs.py` decides admission.
`adapters/agent_audit.py` interprets native output. `agents/bundle_validation.py` verifies archived
relationships and recomputes semantic hashes without target execution. `agents/semantics.py`
defines the explicit projection.

Containers deny networking, use read-only roots/input mounts, non-root identity, dropped
capabilities, no-new-privileges, 2 CPUs, 2 GiB memory/swap ceilings, 256 PIDs, 256 MiB noexec
temporary space, 120-second stage timeouts and bounded streams. Runs are sequential. No host
home, Docker socket, credentials or keys are mounted. Trusted worker source is copied/hashed
separately. Python targets are never imported; MCP commands are never started. The scanner sees
`/target`, not host-parent configuration. Config files and potential inline suppression markers
are refused, not silently removed or neutralized.

## Evidence Contracts

- Retain request, case registry, input bytes, profile/tool/rule selection, worker-code identity,
  both stage streams and receipts. Every retained file has a descriptor/hash.
- Add request/report/parser/run-details schemas under `schemas/agent-v1`. Existing Finding,
  coverage and Summary shapes remain unchanged. Skipped-file/rule counts in the agent parser
  report are null. Its error-record count is zero because native JSON exposes no structured
  error list; stderr is retained separately and creates an explicit review-required failure.
  Parser `complete` describes native record parsing, not complete scanner coverage.
- `agent-details.json` records admission/blockers, attempted scanner launch, input integrity,
  stage timing, native aggregate counts and per-artifact assessments. Refused/unparsed native
  counts are null. Legacy Summary zeros mean zero stored records, not a clean scan.
- Preserve overlapping reports, native confidence/mappings, suppressed boolean and suppression
  tier without promoting them to calibrated risk, actionability or confirmed vulnerabilities.
- SARIF findings use `kind: review`. Suppression is `external/underReview`, not platform approval.
  MCP fallback line numbers are omitted from normalized locations; raw assertions remain intact.
- Common reports with agent sources use `common-report-v2`, `kind: agent-static`, and detailed
  admission/coverage state. Legacy-only reports stay v1. Never sum heterogeneous finding units.
- RunRecord accepts `agent-run-semantic-v1` alongside existing `run-semantic-v2`; older defaults
  and projections remain unchanged. The agent semantic document is retained and verified offline.

## Interpretation

Even matching aggregate file counts cannot identify which files/rules completed. Admitted runs
remain partial. No native observation gives an unknown per-file assessment/count, even when the
aggregate finding count is zero. The generic assessment is not an automatic verdict on either
fixture property: inspect evidence, not just rule IDs, before attributing detection.

Semantic comparison excludes run/execution/record IDs, blob locators, stage timing and only
native `scan_timestamp`/finding `detected_at`. It retains ordering, unknown native fields,
statuses, counts, policy, input identity and tool/worker identity. Byte hashes protect originals;
they are not signatures or protection against an administrator rewriting everything.

Stage timings measure wall-clock processes. Total time starts before preparation and ends before
final report serialization/validation: it includes preparation/cleanup but is **not full CLI
latency**. Host Docker-client RSS is not scanner memory. No performance inference is supported:
host caching, cold starts and load are uncontrolled.

## Observations and Remaining Gates

Final local verification passed 337 tests on Windows and offline Linux Docker, plus format,
lint and mypy. The final 15-run CLI matrix passed and three Python-positive semantic hashes
agreed. Offline mixed reporting combined retained Semgrep, KICS, dependency and agent evidence
as five separate SARIF runs. All 590 checked original bundle files remained byte-identical.
Local execution receipts are under `workspace/phase3-agent-runner-2026-10-02/`; they are not
distributed with this checkout. Earlier failed/development attempts remain recorded separately.

The matrix uses six admitted cases, seven refusals and two extra positive repeats. Python
positive produced four overlapping reports; MCP positive produced one broad filesystem report.
Corrected and near-miss cases produced no native reports. Policy/malformed/unsupported cases
never launched the scanner. Target bytes stayed unchanged; positive repeats agreed semantically.

The eval example still receives upstream shell-injection mapping/advice from AGENT-001.
Preserve the discrepancy rather than endorse or silently repair it. The MCP observation proves
a configuration declaration, not effective host access. Suppression preservation is additionally
tested with authored native reports; inline-suppressed targets remain refused by this treatment.

Next gates: exact-case review, repeatable image preparation, justified research profiles and
separate admission of a pinned source/config pilot. No precision/recall, broad framework support,
runtime security, held-out evaluation or production-readiness claim. Skills, prompts, memory
and UI remain open. These development inputs must never become held-out cases.
