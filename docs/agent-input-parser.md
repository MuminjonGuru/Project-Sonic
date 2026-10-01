# Agent Input Guards and Native Parser

Recorded 2 October 2026. Second bounded agent integration increment, following
[the artifact contracts](agent-artifact-contracts.md). This is library implementation and
engineering verification, **not an integrated scanner command or a new repository benchmark**.

## Implemented Flow

```text
explicit source bytes + path + declared artifact kind + snapshot identity
  -> validate_agent_input: hash, syntax/shape, parse state, possible policy markers
  -> plan_agent_input_admission: validate file identities, refuse unhandled policy
       -> admitted input plan OR explicit blockers (no automatic target rewriting)

retained Agent Audit 0.20.0 JSON bytes
  -> parse_agent_audit_json: bounded strict decoding, pinned shape, counter consistency
  -> normalize_agent_audit + checked input identities
       -> existing Finding records, native assertions, blob hash + JSON pointers
       -> native file count; per-file coverage remains not-observable

NEXT: restricted runner + process/status accounting + bundle storage/validation
      + artifact assessments + CLI + common reporting/export
```

No new dependencies, scanner execution, target imports/installations, MCP invocation, model
calls or detector were added. Existing Semgrep, KICS and dependency code/contracts are unchanged.

## Input Boundary

`agents.inputs.validate_agent_input` accepts already-read bytes, not an arbitrary directory.
Python input is UTF-8 `.py` source parsed with the locked Python 3.13 environment. MCP input is
UTF-8 `.json` containing an explicit `mcpServers` object with local `command` strings and `args`
string lists. Optional `env` values must be strings. Remote/mixed transport declarations and
other configuration families are unsupported; they are not labelled safe. Empty declarations
are syntactically valid but do not establish analysis coverage. Additional fields remain in
the original bytes; their semantics are not validated by this bounded shape check.

| Guard | Current behavior |
|---|---|
| Source bytes | Maximum 256 KiB per explicitly checked artifact |
| Python AST | No imports/execution; at most 50,000 nodes after parsing |
| JSON | Strict UTF-8, object root, no duplicate keys, non-finite numbers or invalid Unicode scalars |
| JSON structure | Maximum depth 64 and 100,000 nodes after decoding |
| Paths | Canonical relative, portable file names; no traversal, alternate streams or Windows reserved names |
| Snapshot names | Reject duplicate/case-colliding paths and ambiguous checked identities |
| Parse outcome | Invalid syntax/shape is malformed; budget exhaustion is failed; unhandled format is unsupported |

Byte/node/depth guards **are not a process sandbox**: JSON decoding and AST construction occur
before the structural counts. The caller must bound file reads and run untrusted parsing in a
resource-limited worker/container. That production intake wrapper is not implemented here.
This increment was exercised only on authored data and retained authored preflight evidence.

## Conservative Policy Admission

`agent-input-policy-v1` refuses the nominated batch if:

- Any snapshot path has a configuration basename `.agent-audit.yaml`, `.agent-audit.yml` or
  `agent-audit.yaml`, conservatively including nested paths and case variants.
- An explicitly checked input is malformed, failed or unsupported, or none is eligible.
- Python is located in a known upstream default-exclusion directory (`.git`, `venv`, `.venv`,
  `__pycache__`, `dist`, `build`, `node_modules`, `.tox`, `.pytest_cache`).
- A checked input contains a possible `# noaudit` marker, including matching text in a string.

Marker presence is a **policy-review trigger**, not proof that upstream honored a suppression
or that the source is vulnerable. This conservative rule can refuse benign text/configurations;
count those refusals as admission limitations, not detector false positives or clean scans.
No YAML is loaded and no target file is changed, removed or silently neutralized. A future
explicit policy treatment must be separately described and tested.

The helper only sees the provided inventory. It cannot prove that the caller listed every file,
read the claimed bytes, excluded symlinks, or isolated scanner parent-directory configuration.
The runner must validate the snapshot/input-view relationship, enforce the admitted plan, and
control parent paths inside the scanner container before any public source pilot is allowed.

## Native Mapping

`adapters.agent_audit` supports the retained **0.20.0** JSON contract and `/target` mount only,
with a 2 MiB decoding budget. Required fields and types are strict; inconsistent native totals,
severity/category/tier counts, suppression counts and pinned-native actionable counts fail.
The actionable predicate is only a producer-counter consistency check, not an analyst metric.
Risk/confidence values are preserved, not validated as measures of security effectiveness.

The pinned source examined is revision `8c4c5cb9bddd4758b064577c912ee8afcaf5330f`, notably
`cli/formatters/json.py`, `models/finding.py`, `config/ignore.py` and
`scanners/python_scanner.py` below upstream `packages/audit/agent_audit/`. The
[preflight guide](agent-audit-preflight.md) records candidate provenance and eligibility limits.

Unknown extra fields remain in parsed/native evidence and their JSON paths are recorded.
Full native findings, including suppression state, remediation and metadata, remain under
`Finding.native_extension.agent_audit`. Root-level extras/counters remain in the parsed document
and original bytes. Every finding references the original SHA-256 and `/findings/N` pointer.
The parser itself does not persist blobs; the integrated runner must do so before parsing.

Normalization rechecks the retained bytes to reject mutation of parsed models or blob identity.
It maps findings only to checked, parsed inputs from the supplied snapshot. Python line ranges
must fit the validated source. Column conventions are not admitted yet, so columns stay only in
native evidence. MCP fallback lines become path-only locations, not invented line precision.

Severity mapping `agent-audit-severity-v1` maps critical/high/medium/low directly and info to
informational; unknown labels remain unknown. Only observed CWE/OWASP mappings are copied.
The eval preflight's `AGENT-001` shell-injection mapping/remediation remains unreviewed and
explicitly flagged. Missing MCP CWE is not filled from the builtin rule pack.

Overlapping and suppressed findings are retained individually. Fingerprints are record/candidate
identifiers, **not** deduplication decisions or whole-run repeatability hashes. No property label
is inferred solely from a native rule ID. Suppression-aware report/export behavior still needs
integration tests before these records can enter the user-facing common-report path.

Native aggregate `scanned_files` cannot establish per-file/per-property completion. Therefore
the normalizer reports `per_file_coverage = not-observable`, including zero-finding documents.
Native exit code, stderr diagnostics, output truncation/timeouts, input admission, and bundle
validation must remain separate when the runner assigns platform outcomes.

## Verification and Remaining Work

- Final Windows: **294 passed**, 14.05 seconds; format/lint/mypy passed.
- Final pinned Ubuntu Docker suite: **294 passed**, 8.25 seconds, offline, read-only source,
  non-root, two CPUs, 2 GiB memory. Project tests, not scanner performance measurements.
- Added **122 tests** beyond the prior 172-test contracts increment.
- Read-only replay: all **12** retained native outputs parsed; **17** Python/MCP findings retained
  across 11 normalizable documents. The skill finding was refused as unsupported. These counts
  include repeats/overlaps, not unique vulnerabilities or independently confirmed findings.
- Applying the current refusal policy to historical source views admits six and blocks six.
  The earlier neutral-overlay diagnostic remains blocked by the new baseline policy; no
  historical result was rewritten. All **735** preflight evidence files remained byte-identical.
- Earlier test attempts are retained: an initial Windows pytest setup failure caused by very
  large generated case names was fixed with short IDs; 292-test runs preceded two edge-case tests.

Local evidence is under `workspace/phase3-input-parser-2026-10-02/`, with final logs in
`verification-final/`, `linux-verification-final/`, and `replay-final/`. Raw workspaces remain
outside Git. No fresh GitHub CI run, independent adjudication or public-source scan is claimed.

Next: bounded validation worker; manifested input views and trusted container policy; scanner
execution/status accounting; persisted evidence and assessments; CLI/common reporting; controlled
repeats. Only then review and admit a pinned source/config pilot. Broad agent coverage, UI and
held-out benchmarking remain separate work.
