# Memory/State Security Repair v1

Date: 20 October 2026. Fourth of seven submitted scanner-family repairs.

## Authority and Status

The student requested the next repair after accepting the filesystem increment. This continues
the approved defensible-evidence policy: preserve IDs, remove unvalidated scores, distinguish
ordinary features from review conditions and expose unsupported analysis. Original authorship
is student-declared. Repairs and syntax expectations are AI-assisted, not independent labels,
mentor approval or a held-out research benchmark.

Both supplied parts were reviewed, including the extension's MCP parser, repeated scoring
function and CLI. There are **18 formal IDs: 001-010 and 101-108**. Error marker 099 and ad hoc
MCP marker MCP-001 remain non-emitting metadata, not additional active rules.
Original Markdown and inert extracted payloads are unchanged and hash-verified.

The package module and restricted JSON worker are **development-only**. They are not enabled
in ordinary CLI scan profiles, common reporting, SARIF, HTML or either public pilot.
No target execution, memory-store access, network requests or model calls occur.
The existing MCP analyzer remains responsible for MCP; this repair does not expand its coverage.

## Implementation

- [Rule/status registry](../src/agentsec_evidence/custom_rules/memory_catalog.py).
- [AST detector](../src/agentsec_evidence/custom_rules/memory_state.py).
- [Exact-input worker](../src/agentsec_evidence/custom_rules/memory_worker.py):
  separate `memory-development-v1` result and repaired version `1.0.0`.
- [60 authored controls](../test_cases/development/memory-state-v1/cases.json).
- [Rule tests](../tests/unit/test_memory_rules.py) and
  [worker tests](../tests/unit/test_memory_worker.py).
- [Finite offline rehearsal](../tools/verify_memory_state_repair.py).

Shared lexical-resolution helpers and all three earlier detector families remain unchanged.
The repaired version is a separate lineage from the submitted draft's version label.

## Rule Interpretation

All prefixes are `MEM-SEC-`. **Four static review conditions, eleven inventory entries and
three deferred entries** do not constitute 18 demonstrated vulnerability classes.

| Suffix | Status | Actual observation and boundary |
|---|---|---|
| 001 | Inventory | Memory-persistence API naming cue. Actual API, storage and destination remain unknown. |
| 002 | Deferred | Shared-state tampering requires storage semantics, writers, provenance and an access/isolation policy. |
| 003 | Deferred | Context-injection success cannot be established from names such as `user_input` or `llm_output`. |
| 004 | Condition | Credential-like identifier in serialization input. No secret validity, persistent storage or exposure is established. |
| 005 | Inventory | LangChain-family import declaration, including explicitly named LangGraph packages. Not installed-version or runtime memory support. |
| 006 | Inventory | AutoGen-family import declaration. Not framework execution or security. |
| 007 | Deferred | No invented MCP state-store schema or permissions. Existing analyzer ownership is unchanged. |
| 008 | Inventory | Memory-like expression passed to stream serialization. Not proof of disk storage, full history or confidential contents. |
| 009 | Inventory | Memory/context-like reference in an assignment. Not cross-turn influence or injection. |
| 010 | Inventory | Memory-like expression passed to JSON/Pickle/YAML serialization. Not a later unsafe-loading claim. |
| 101 | Inventory | Memory-like slice or context-bound setting. No model capacity, tokenizer or overflow measurement. |
| 102 | Inventory | Summarization/compression naming cue. Normal summarization is not poisoning. |
| 103 | Condition | Direct memory-like expression passed to resolved builtin `eval`/`exec`. No cross-statement taint or attacker control. |
| 104 | Condition | Direct memory-like expression in print/log arguments or supported HTTP `data`/`json` body syntax. Not proof of transmission, confidentiality or exfiltration. |
| 105 | Inventory | Memory/state attribute assignment or update naming cue. Receiver identity and authorization remain unknown. |
| 106 | Inventory | Memory-version/snapshot naming cue. Versioning itself is not a vulnerability or integrity guarantee. |
| 107 | Condition | Nonliteral content in a literal system-role mapping or supported resolved `SystemMessage` constructor. Not proof the object reaches a model or poisons it. |
| 108 | Inventory | Session/user identifier naming cue. No conclusion about reuse, tenant isolation or effective authorization. |

004/104 use low review priority; 103/107 use medium. These are provisional triage priorities,
not validated severity, confidence, CVSS or overall risk scores. Normal program configurations
can produce these conditions; source/context review is mandatory before a vulnerability claim.
Generic unused dictionaries can match 107's declared shape, a deliberate and explicit limit.

## Repair Rationale

The draft contained syntax/transport defects and `Finding` calls with an undefined
`file_line_range` field. Broad exception handling mislabeled runtime failures as parse/security
findings. Nested dictionaries also broke hash-based deduplication. These are replaced by
typed records, deterministic source-bound identity and separate failure states.

The call-name prefilter skipped important cases such as `eval`, logging and many context APIs,
while nearby-line regexes could attach unrelated evidence to a call. Assignment patterns were
tested only near selected calls rather than inspected as assignments. The new detector uses
bounded AST nodes, conservative import/alias resolution and explicit per-construct limitations.

The duplicate scoring function combined arbitrary modifiers and could produce confidence above
one. Normal truncation, compression, versioning and session identifiers were scored as danger
without measuring tokens, trust, content or authorization. All such scores and verdicts were
removed. `max_context_window` did not establish real overflow analysis and is not retained.

The guessed MCP `state`/`memory` shape, default root/read-write assumptions and swallowed
configuration errors are not carried forward. Nor are raw secret matches, source snippets,
randomized hashes, alphabetic severity ordering or the JSON-mode CI-exit defect.
Unsafe/misleading advice such as masking memory "before exfiltration" is removed.

## Supported Syntax

- JSON `dump/dumps`, Pickle `dump/dumps`, PyYAML `dump/safe_dump`: explicit value argument.
  Literal secret values are not detected; names and explicit expression containers are inspected.
  Mapping keys, runtime object fields and actual serialized contents are not traced.
- Builtin `eval/exec`: explicit first argument. Assignment aliases, transformation calls,
  conditional expressions and cross-file flow are not followed.
- Builtin `print` and module-level `logging` functions: explicit text/message arguments.
  Assigned logger instances, log destinations, levels and runtime filtering are not modeled.
- Requests/HTTPX module `post/put/patch/request`: explicit `data` and `json` expressions.
  Library-specific argument shapes are separated. `content`/`files` fields are explicitly
  unsupported; headers, query values and endpoints do not become body-flow observations.
  Conflicting body options are not resolved to the effective transmitted body.
- `langchain_core.messages.SystemMessage`, its `system` module export, and
  `langchain.messages.SystemMessage`: direct `content`, with limited metadata options.
  `content_blocks`, type overrides, unknown/expanded or duplicate arguments remain unsupported.
- A dictionary with unambiguous literal `role: system` and nonliteral content is a message-shaped
  declaration only. Duplicate/unpacked/dynamic roles have explicit limitations.
- Names, import declarations, assignments, slices and simple call names provide inventory.
  They do not establish agent identity or framework semantics.

Names are heuristics. A variable named `memory` can contain unrelated public data, and a real
memory value with a different name may be missed. No sanitizer or trusted-source assertion
is inferred from names. Calls containing unknown transformations expose limitations even when
another part of the expression also matches a direct condition.

Lambda/comprehension bodies and annotations are excluded. API shape validation is deliberately
bounded, not complete Python type/value checking. Custom encoders, representers and callbacks
remain unmodeled. Local replacement modules, monkey-patching and effective runtime bindings
remain unknown. Raw memory dumps/config files are not inspected by this Python worker.

### Primary References

Reviewed on 20 October 2026 to establish syntax, not universal version compatibility:

- [Python JSON](https://docs.python.org/3.13/library/json.html):
  `dump` writes to a file-like object; `dumps` produces a string.
- [Python Pickle](https://docs.python.org/3.13/library/pickle.html) and
  [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation): serialization versus loading is distinct.
- [Python logging](https://docs.python.org/3.13/library/logging.html):
  module-level message and formatting arguments.
- [Requests](https://requests.readthedocs.io/en/latest/api/) and
  [HTTPX](https://www.python-httpx.org/api/): different call/option signatures and body fields.
- [LangChain SystemMessage](https://reference.langchain.com/python/langchain-core/messages/system/SystemMessage)
  and [message exports](https://reference.langchain.com/python/langchain/messages):
  system-message construction, not proof of downstream model invocation.

Standard-library signatures were also inspected in the provisioned Python 3.13.15 runtime.
Online Python 3.13 documentation displays a newer patch release; the lock and retained image
identify the tested runtime. No target framework or project dependencies were installed.

## Isolation, Evidence and Result States

The worker validates exact inventory/selection, byte lengths and SHA-256 values, then rechecks
selected bytes. Limits: 64 files, 1 MiB aggregate, 256 KiB per input, 50,000 AST nodes and
1,000 observations per file, plus a 512-entry traversal guard. Links and junctions are refused.

Malformed, unsupported and failed files retain **null findings**. Empty selection is not
successful analysis. `complete` means bounded processing returned, not complete security
coverage: report-level limits and per-file uncertainty records still apply.
Exit 0 means no configured priority threshold was breached; 1 means a threshold was breached;
2 means partial, empty or refused processing. No target suppressions are applied in this mode.

Output preserves fixed evidence tokens, canonical API identity, source-bound IDs and UTF-8
source locations. Raw snippets, source identifier spellings and secret values are omitted.
Artifact paths/hashes remain identifying. Retained source snapshots are not redacted, and
bundle verification is not redistribution approval or independent attestation.

## Controlled Rehearsal

Local bundle: `outputs/memory_state_repair_2026-10-20-final/`.

| Treatment | Selected files | Condition findings | ID-bearing inventory | State / exit |
|---|---:|---:|---:|---|
| Full controls, repeat 1 | 60 | 10 | 24 | partial / 2 |
| Full controls, repeat 2 | 60 | 10 | 24 | partial / 2 |
| Valid syntax only | 59 | 10 | 24 | complete / 1 |
| Fixed/near-miss controls | 6 | 0 | 1 | complete / 0 |

The deliberately malformed input accounts for partial processing. Seventeen valid cases also
carry explicit limitations. The one inventory entry in fixed controls is intentional.
Expected rule/inventory IDs, states, complete input accounting and source hashes matched.
Both full-control native reports are byte-identical:
`0ee258dbe758f436b16a22c0db9c437e6ab87fe74e286b3f37c03c621488cf8e`.

These are AI-authored engineering assertions, not independent security labels, precision/recall,
confirmed vulnerabilities or public-project measurements. Test/static-check/backup receipts
and the separate closeout remain under `workspace/memory-repair-2026-10-20/` and `outputs/`.

To repeat, use a new destination:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_memory_state_repair.py `
  --output outputs/memory-state-repair-new-attempt
```

Source is snapshotted and verified before read-only mounting. Image:
`sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080`.
Workers run sequentially, offline, non-root, read-only, with dropped capabilities, 1 CPU,
512 MiB memory, 64 processes and bounded temporary storage. No Docker socket or host home
is exposed. This reuses the existing local image, not a clean-machine image rebuild.

## Next

Repair agent self-modification next, then orchestration and agent-to-agent. Reporting adapters,
suppression policy and separately admitted paired public testing remain later gates.
Nothing here alters historical pilot outcomes or authorizes a commit/push.
