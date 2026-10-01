# Agent-Static Integration: Preflight Checkpoint

Recorded 2 October 2026, Asia/Tashkent. This is a summary of local engineering evidence,
not an integrated feature, independent accuracy evaluation or academic approval. Execution
timestamps are UTC and begin on 1 October. No new public agent repository was scanned.

## Scope and Starting State

The student confirmed Python tool definitions and MCP JSON configurations as the first
agent-specific integration scope. The bounded preflight used authored LangChain-style
decorated tools without importing LangChain or executing target code. This does not establish
full framework support. Skills, prompts and memory remain broader inventory/later-check work.

Existing Semgrep, KICS, dependency and common-reporting behavior remains unchanged. The
previous public repository is still admitted for its dependency experiment only. There is
no Agent Audit command in the platform CLI yet.

| Baseline check | Recorded result |
|---|---|
| Starting source | `cfff2eb57b9f6d304fb7254cbbdbc3dd30da3c5c`, plus existing uncommitted handoff documentation |
| Python | 3.13.15 |
| Host uv | 0.12.13; recorded drift from 0.12.6, not a dependency-lock update |
| Lock and installed dependencies | Offline lock check and `uv pip check` passed |
| Windows quality checks | Formatting, lint, mypy and 115 pytest tests passed |
| Container readiness | `doctor --strict` passed; Docker 29.7.2 with Linux containers |
| Recovery | Git bundle restored and checked; 10,930 archived files restored and individually verified |

These are retained preflight results, not a new CI run for this documentation change. A fresh
Ubuntu application test suite was not run. Same-device backup remains vulnerable to device loss.

## Candidate and Execution Boundary

- Upstream: [Agent Audit pinned source](https://github.com/HeadyZhang/agent-audit/tree/8c4c5cb9bddd4758b064577c912ee8afcaf5330f),
  version 0.20.0, revision `8c4c5cb9bddd4758b064577c912ee8afcaf5330f`.
- MIT notice retained locally. This is not blanket approval of dependency licensing or
  redistribution of third-party source, fixtures or reports.
- Source archive SHA-256:
  `2e828fca2ee59842b7dc3c5cce111078b17625849d6e5080034d5363464634c7`.
  All 580 materialized files were checked against the pinned Git tree.
- Local runtime image ID:
  `sha256:e4b41016ff8cd5b5c769f171cca3f3f145a8312a3fb2a0ad72993b11a636e79a`.
  This is not a registry digest or a promise that the image exists in a fresh checkout.
- Source and dependencies were prepared inside Docker, then installed offline from a retained
  hashed wheelhouse. This used a new compatibility lock, not upstream's exact Poetry environment.
  The application lock and host application dependencies did not change.

The tested invocation was `scan /target --format json --severity info --fail-on high --no-color`
inside the pinned image. It used read-only inputs/root, disabled networking, non-root identity,
dropped capabilities, no-new-privileges, 2 CPUs, 2 GiB memory, 256 PIDs, a bounded temporary
filesystem, a 120-second timeout and bounded output streams. No host credentials, Docker socket,
live inspection, target installation or agent execution were supplied. Optional model-backed
judging was absent (`NullJudge`). This does not certify every upstream execution mode or every
dependency. Scanner dependency vulnerability and full redistribution reviews remain separate.

## Observed Smoke Results

Twelve executions covered nine fixture directories and ten treatments. Expectations were
AI-authored engineering assertions, not independently reviewed final benchmark labels.

| Treatment | Runs | Native exit | Native files/findings per run | Observation |
|---|---:|---:|---|---|
| Python tool parameter reaches `eval` | 3 | 1 | 1 / 4 | Overlapping reports, not four confirmed vulnerabilities |
| Corrected bounded example | 1 | 0 | 1 / 0 | No finding on this example |
| Benign eval-shaped string | 1 | 0 | 1 / 0 | No finding on the near-miss |
| Malformed Python | 1 | 0 | 0 / 0 | Parse warning on stderr; not clean |
| Unsupported text | 1 | 0 | 0 / 0 | Unsupported/not applicable |
| Positive input excluded by target-local config | 1 | 0 | 0 / 0 | Automatic policy lookup hid coverage |
| Same excluded input with trusted neutral config overlay | 1 | 1 | 1 / 4 | Positive result restored without editing source files |
| MCP JSON with unversioned server command | 1 | 1 | 1 / 1 | Native rule `AGENT-029` |
| Malformed MCP JSON | 1 | 0 | 0 / 0 | Parse warning on stderr; not clean |
| Skill Markdown diagnostic | 1 | 1 | 1 / 1 | Feasibility observation only; not supported skill coverage |

All attempts completed within bounds and target bytes remained unchanged. The Python positive
case reported `AGENT-001`, `AGENT-017`, `AGENT-035` and `AGENT-034`. Native `AGENT-001` describes
the eval case as command injection/CWE-78 and gives shell-oriented remediation. Preserve and
flag that attribution; do not silently fix it or promote it as verified advice.

The first repeat comparison excluded only `scan_timestamp` and differed. Source inspection
identified per-finding `detected_at` too. The exploratory `agent-audit-preflight-semantic-v2`
projection excludes only those two timestamp fields, preserving other values and ordering.
Three positive runs and the neutral-overlay result then shared semantic SHA-256:

`585378c34ff3c798172c870a1975ac447136f8f49d104dcdd3221da536bd1252`

Original bytes and the first unsuccessful comparison were retained. This is not proof of
universal determinism or a preregistered confirmatory endpoint.

## Required Before Integration Acceptance

1. Inventory eligible inputs independently and validate syntax without executing target code.
   Malformed, unsupported, excluded and unknown coverage must not become successful no-finding scans.
2. Control automatic policy lookup for all supported config filenames and parent directories;
   account for inline suppressions. Preserve originals and manifest any neutral overlay or derived view.
3. Preserve raw bytes before parsing. Keep native exit status separate from platform analysis
   status; exit 1 may mean findings, while exit 0 alone does not prove complete analysis.
4. Validate native fields, counts and paths; link normalized records to native evidence.
   Preserve mappings/suppression details without treating native confidence, actionability or
   risk scores as validated platform measurements.
5. Reuse existing orchestration and reporting contracts, with backward-compatibility tests.
   Do not combine heterogeneous finding units into an overall vulnerability count.
6. Review finite Python/MCP expectations, test failure/suppression paths and repeatability,
   then separately admit a pinned public repository's source/config scope.

## Evidence Availability

Local receipts, raw outputs, source, locks, wheelhouse and authored cases remain under
`workspace/phase3-preflight-2026-10-02/`, intentionally ignored by Git. The closed evidence
manifest SHA-256 is:

`4640b5bae4817aeb35192c618fd20e83ac0e2783a566e74142c3a9906911746b`

It records 735 files and the associated planning checkpoint. Checksums identify retained bytes;
they are not signatures, external attestations, or proof that a fresh checkout contains the
evidence. Later documentation changes do not rewrite that historical manifest.

This checkpoint publishes only a factual summary and engineering boundaries. Reusable build
recipes, reviewed test fixtures, contracts and adapter implementation should enter source
control in subsequent focused changes; the exploratory workspace is not a distributable tool.
