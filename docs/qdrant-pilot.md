# Qdrant MCP Pilot: Admission, Execution And Replay

The student approved a second public formative target on 18 October 2026. See the exact
[admission](../test_cases/pilot/qdrant-mcp/ADMISSION.md) and
[intake specification](../test_cases/pilot/qdrant-mcp/intake-spec.json).
Input preparation alone grants no scan permission. The separate approved execution is implemented
by `agentsec_evidence.pilot.qdrant`; it does not widen the original fixed-repository runner.

## Why This Project

[Qdrant's MCP server](https://github.com/qdrant/mcp-server-qdrant/tree/c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41)
is a compact Python/FastMCP application with real search/store tools, a checked-in MCP client
configuration, a skill artifact, tests and a root uv lockfile. Selection preceded security
scanning and did not require finding a vulnerability. It extends the earlier LangGraph case with
an actual MCP declaration without requiring a database service or paid account for static analysis.

The bounded shortlist also considered MotherDuck's Python MCP server and the official MCP
reference-server collection. They were not rejected as insecure or unsuitable: Qdrant provides
a small standalone source tree and a useful mix of observable artifacts. Repository count is
not representativeness; this is a purposive formative pilot, not held-out final evidence.

## Observed Input Result (Pre-Scan Record)

- 34 files / 539,332 bytes matched the full pinned commit/tree/blob evidence and source archive.
- No symlink, submodule, Git LFS pointer or incomplete tree was admitted.
- 19 Python files (15 source, four test-directory files), one MCP JSON and one skill candidate.
- Existing lockfile parser: 111 eligible PyPI name/version pairs, plus one local project root.
- Full-parent policy review, exact-byte views and three isolated syntax workers passed.
- Existing 68 rules, five required images and frozen database were present and verified.
- 127 platform source files stayed unchanged during successful preflight.
- Closeout passed 239 focused Windows tests and replayed 691 manifest entries, four input
  plans and three syntax-response bindings. No fresh full-suite or Linux-suite run is claimed.
- **Zero security scanners, target tests or target code executions in this preflight.**
  This historical receipt does not describe the later execution increment.

Private evidence is under `workspace/phase4-mcp-candidate-2026-10-18/`: acquisition, prepared input,
per-tool plans, lockfile declarations, source/configuration checkpoints and process receipts.
That directory is intentionally not distributed in Git. Raw source and native evidence require
separate disclosure/license/redaction consideration; this document grants no public release.

## A Compatibility Detail To Preserve

Agent Audit and Semgrep input requests can contain the same path/hash/size/media-type records
in different orders. Qdrant's nested tree exposes this. A request-bound parser report cannot
be reused by comparing only the sets or rewriting its request hash.

Preflight checks equal selected path-to-record maps and snapshot identity, while retaining each
original request and running its own worker. Both Python request orders remain recorded.
The execution implementation includes a regression for this condition: equivalent file maps do
not permit reusing a worker response bound to a differently serialized request. Historical
models and evidence remain unchanged.

## Attempt History

1. `preflight-01`: local helper omitted the required runtime-directory argument; zero workers.
2. `preflight-02`: exact request equality failed on different inventory order; zero workers.
3. `preflight-03`: separate request-bound workers, all input gates passed; three syntax workers.

Each attempt is retained separately. Earlier helpers are retained alongside their hashes.
The first two failures are assessment-helper/integration assumptions, not target vulnerabilities
or security-scanner failures. Original product code, source inputs and tool rules were unchanged.

## Execution Contract

Keep Semgrep's research and policy views, Agent Audit's Python and MCP results, and the three
dependency stages separate. Bind every selected/excluded file to the full verified inventory.
Use the existing bounded producer APIs with a new explicitly admitted plan; do not change the
old `PilotPlan` literals or label Qdrant evidence as the original public pilot.

The new `qdrant-repository-pilot-report-v1` envelope has 21 ordered rows: seven stages for each
of three sequential repetitions. Each repetition runs three isolated request-bound syntax
workers before the security tools. Inputs, original 68 rules, configurations, image identities,
trusted source and database are frozen; guards check for changes between stages. Every attempt
gets a new directory. Failure preserves the attempt without silent retry or fabricated zeroes.

Native JSON, Semgrep native SARIF, Agent Audit normalized findings and project SARIF, dependency
bundles, dual-view accounting and a CSV table are retained. Offline replay checks the full seal,
Git/source/views, syntax bindings, exact static/dependency invocations, native normalization,
exports and semantic results. It invokes no Docker container. Full replay currently requires
the original local execution paths and the frozen database; this is not a portability claim.

The explicit stage names `agent-python` and `agent-mcp` identify their different input surfaces.
The unchanged Agent Audit configuration's historical Python treatment label is not used to
relabel MCP evidence or claim framework recognition. Native report severities and confidence
remain unreviewed tool assertions. Dependency observation states of `complete` do not establish
per-package matching completeness or installed runtime exposure.

### Invocation

From the development checkout, with the previously prepared local cache, rules and database:

```powershell
.venv\Scripts\python.exe -X utf8 -m agentsec_evidence.pilot.qdrant run `
  --project "$PWD" `
  --cache "$PWD/workspace/phase4-mcp-candidate-2026-10-18/acquisition-01/cache" `
  --rules "$PWD/workspace/phase3-semgrep-broad-assessment-2026-10-05/upstream-full-01/source" `
  --database "$PWD/workspace/dependency-preflight-2026-09-18/database/osv-scanner/PyPI/all.zip" `
  --output "$PWD/workspace/phase4-qdrant-pilot-2026-10-18/NEW-ATTEMPT"

.venv\Scripts\python.exe -X utf8 -m agentsec_evidence.pilot.qdrant verify `
  --project "$PWD" `
  --database "$PWD/workspace/dependency-preflight-2026-09-18/database/osv-scanner/PyPI/all.zip" `
  --output "$PWD/workspace/phase4-qdrant-pilot-2026-10-18/EXISTING-FINISHED-ATTEMPT"
```

The output's parent must already exist. The run command never downloads dependencies, source,
rules, images or vulnerability data. This narrow module CLI is not arbitrary-project scanning.
`repository-pilot-report.json` is intentionally distinct from the original `pilot-report.json`.

**Next:** Bind this new evidence contract into common reporting and HTML, with Python/MCP rows,
policy differences, dependency identities and omissions preserved. Do not feed it to the old
fixed-pilot loader or claim the new target already has a verified HTML report.

No custom detection rule, new framework-wide coverage or independent vulnerability labels are
established by this implementation. Existing conditioned development cases remain separate.
