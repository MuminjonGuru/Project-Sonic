# Filesystem-Access Repair v1

Date: 20 October 2026. Third of seven submitted scanner-family repairs.

## Status and Authority

The student approved the same defensible-evidence policy: remove unvalidated entropy,
depth and trust scores; distinguish ordinary filesystem activity from risk conditions;
preserve IDs with explicit status; leave MCP analysis with the existing analyzer.
This is a student working decision, not independent review or mentor approval.
Original code provenance is the student's authorship declaration. The repair and controlled
expectations are AI-assisted work, not independently established security ground truth.

The repaired module and isolated JSON worker are in the development package. They are
**development-only**, not enabled in ordinary scan profiles, common reporting, SARIF,
HTML or public pilots. No target code is executed or installed; no target-named file is opened.
There is no new general-purpose SAST engine or claim of measured real-world accuracy.

## Supplied Source and Count Reconciliation

The student explained that multipart code was in the same document. A full reinspection of
`new_rules/filesystem_access_draft.md`, its fences and the extracted payload found one
Python block, source lines 4-822, containing **12 formal rule definitions: 001-012**.
Its heading claims 24 rules, but no additional 101+ definitions were present in the supplied
bytes. The repair covers all supplied code; it does not manufacture missing definitions.
Later-supplied content would require a new, separately hashed import.

Two additional emission markers are preserved as non-emitting legacy metadata:
`FS-ACCESS-099` was a parse/error diagnostic and `FS-ACCESS-MCP-001` was an ad hoc MCP
trust heuristic. They are not counted as active security rules.
Original Markdown, extracted payloads, extraction ranges and hashes remain unchanged.

## Implementation

- [Rule/status registry](../src/agentsec_evidence/custom_rules/filesystem_catalog.py).
- [Bounded AST detector](../src/agentsec_evidence/custom_rules/filesystem.py).
- [Exact-input worker](../src/agentsec_evidence/custom_rules/filesystem_worker.py),
  separate `filesystem-development-v1` contract.
- [54 authored development cases](../test_cases/development/filesystem-v1/cases.json).
- [Rule tests](../tests/unit/test_filesystem_rules.py) and
  [worker tests](../tests/unit/test_filesystem_worker.py).
- [Offline four-treatment rehearsal](../tools/verify_filesystem_repair.py).

The existing shared lexical-resolution helpers are reused unchanged. This increment does not
change either repaired predecessor, the existing MCP analyzer or any historical profile.

## What the IDs Establish

All prefixes are `FS-ACCESS-`. There are **five active static conditions, five inventory-only
entries and two deferred entries**, not 12 demonstrated vulnerability classes.

| Suffix | Status | Observable condition and limit |
|---|---|---|
| 001 | Active | Nonliteral path expression at recognized filesystem I/O syntax. It can be a constant variable or validated input; attacker/agent control is not established. |
| 002 | Deferred | MCP write-permission claims require an admitted schema and semantics. Existing MCP analyzer remains responsible. |
| 003 | Active | Nonliteral destination at a write-capable call shape or literal write mode. Not proof of arbitrary write, actual execution or effective access. |
| 004 | Inventory | Literal read-path suffix resembles code/configuration. Contents and parsing behavior remain unknown. |
| 005 | Active | Literal parent-directory component at recognized I/O syntax, with separate POSIX/Windows interpretations. Not proof of escaping an allowed root. |
| 006 | Active | Credential-like identifier directly used in a recognized file-write expression. A name heuristic, not proof of a real secret or disclosure. |
| 007 | Inventory | Literal POSIX-style `/tmp` or `/run` prefix. Neither dangerous by itself nor exempt from review. |
| 008 | Inventory | Number of formatted expressions in a path expression. Not entropy, instability or LLM attribution. |
| 009 | Inventory | Lexical component counts of a literal write destination under POSIX/Windows parsing. Not actual directory depth or risk. |
| 010 | Deferred | MCP implicit-trust heuristic removed; no fabricated permission contract. |
| 011 | Active | Direct recognized file-read expression passed to builtin `eval`/`exec`. No cross-statement tracing, attacker provenance or runtime exploitability. |
| 012 | Inventory | Literal write destination has a state-like name/component. Not proof of agent memory modification or poisoning. |

006 uses low review priority; other active conditions use medium. These are provisional
review priorities, not validated severities, confidence values or CVSS scores.
Inventory/deferred entries have no finding priority. There is no overall security score.

## Why the Draft Changed

The supplied code had transport/syntax problems, including invalid special-name spellings and
indentation. `Finding` construction supplied a field missing from its dataclass, and generic
exceptions could become misleading parse/security findings. The repair uses explicit states.

Adjacent-line regexes, substring callee matching and arbitrary path stringification were not
reliable evidence of a security condition. The replacement inspects actual call expressions
with conservative lexical import resolution and shadowing handling.

The draft's empty-string safe-base prefix could match every path. Host-specific `Path` behavior,
arbitrary entropy/depth scores, inverted trust adjustments and invented MCP permission
fields were removed. Pure lexical POSIX/Windows parsing never resolves target paths.
Neither `resolve()` nor the mere presence of a containment-looking call establishes authorization.

Ordinary safe-loader use, temporary files, deep paths and state-like filenames are not labeled
vulnerabilities. Dynamic imports remain with the tool-execution family. Logging-related
credential names remain with the network family. File-write observations here do not leak
the identifier spelling or literal secret values into findings.

Other repairs include deterministic source-bound IDs, numeric priority comparisons,
JSON output before threshold exits, bounded exact file selection and explicit unsupported
input. Random hash identity, alphabetic severity sorting, swallowed parsing failures and
unrestricted target traversal were not carried forward.

## Supported Syntax and Deliberate Limits

| Shape | Treatment |
|---|---|
| `open` / `io.open`, including lexical import aliases | Explicit file argument and literal mode. Integer descriptors are inventory, not paths. Unknown/invalid mode is recorded and cannot establish write capability. |
| Inline `pathlib.Path(one_argument).open/read_text/read_bytes/write_text/write_bytes` | Path syntax and direct write data; bounded Python 3.13 call-shape validation. |
| `shutil.copy/copy2/copyfile/copytree/move` | Explicit source and destination expressions; source-read/destination-write roles. Not recursive contents, deletion effects or permissions. |
| Inline writable `open(...).write(value)` | Direct credential-name heuristic. Assigned handles and transformed write values are unknown. |
| Builtin `eval/exec` with direct recognized file read | Direct syntax relationship only; malformed call shapes do not establish this condition. |
| Inline path transformations or `/` composition | Nonliteral/transformed path; explicit lack of containment verification. |

Assigned `Path` objects/handles, multisegment `Path` constructors, cross-file or cross-statement
flow, aliases through assignments, runtime types, sanitizers, symlink/race conditions, ACLs
and effective permissions are not resolved. Other filesystem APIs, such as `os.open`, are not
covered by this registry. Local replacement modules and monkey-patching remain unknown.
Custom openers/copy functions and other option values are not modeled for behavioral effects.
The call-shape checks are not a Python interpreter or complete type/argument-value validation.

Lambda/comprehension bodies and annotations are outside analysis. Observed ambiguous bindings,
unsupported scopes, expanded arguments, assigned handles and opaque path-like methods receive
explicit limitation records where recognizable. Global limitations also apply when no such
record can be generated. A complete bounded scan is not complete filesystem-security coverage.

### API References

Primary documentation reviewed on 20 October 2026:

- [Python open and evaluation builtins](https://docs.python.org/3.13/library/functions.html):
  file/descriptor arguments and read/write modes.
- [pathlib](https://docs.python.org/3.13/library/pathlib.html):
  pure lexical paths versus filesystem-resolving methods.
- [os.path](https://docs.python.org/3.13/library/os.path.html):
  character prefixes are not path containment.
- [shutil](https://docs.python.org/3.13/library/shutil.html): copy/move parameters.
- [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation): loader choice alone is not
  evidence of arbitrary code evaluation by this detector.
- [MCP roots, dated specification](https://modelcontextprotocol.io/specification/2025-11-25/client/roots):
  not authority to invent the draft's permission/trust schema.

Python method signatures were also inspected in the actual 3.13.15 environment without
executing target code. Online 3.13 documentation may show a newer patch release; the lock
and retained image identify the validation runtime.

## Evidence and Isolation Contract

The worker verifies exact inventory membership, selection, lengths and SHA-256 values, then
rechecks selected bytes. Bounds: 64 inventory files, 1 MiB aggregate, 256 KiB per input,
50,000 AST nodes, 1,000 observations per file and a 512-entry traversal guard.
Links/junctions are refused; selected non-Python inputs are unsupported.

Malformed, unsupported and failed files have **null findings**, not an empty clean list.
Report `complete` means the bounded inspections returned; limitations still apply.
Exit 0 means no requested priority threshold was breached, 1 a threshold was breached,
and 2 partial, empty or refused processing. No target suppressions are applied in this mode.

Findings retain canonical API names, evidence-kind tokens, source hash, stable ID and source
location with UTF-8 byte columns. They omit source snippets, target path literals and secret
identifiers/values. Source artifact paths and hashes remain identifying. Retained inputs and
snapshots contain full source bytes and are not automatically cleared for distribution.

## Verified Development Results

Local bundle: `outputs/filesystem_repair_2026-10-20-final/`.

| Treatment | Selected files | Condition findings | ID-bearing inventory | State / exit |
|---|---:|---:|---:|---|
| All controls, repeat 1 | 54 | 30 | 20 | partial / 2 |
| All controls, repeat 2 | 54 | 30 | 20 | partial / 2 |
| Valid syntax only | 53 | 30 | 20 | complete / 1 |
| Fixed/near-miss controls | 6 | 0 | 2 | complete / 0 |

The intentionally malformed case explains partial processing. Fourteen valid cases also have
explicit limitation observations. Inventory observations in the fixed controls are intentional,
not failed negative cases. Expected IDs, states, selected-file hashes, catalog and inventory
accounting matched. Repeated native JSON is byte-identical:
`20b2f7137c0b2ce40174fd56d61ecb6d66bd525a77d2e9bfc75b9bb55327adf6`.

These are engineering assertions over authored development cases, not independent
precision/recall estimates, held-out results, vulnerability counts or public repository findings.
Static/test receipts and closeout are retained separately under
`workspace/filesystem-repair-2026-10-20/` and the sibling output closeout record.

To repeat, choose a new output directory:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_filesystem_repair.py `
  --output outputs/filesystem-repair-new-attempt
```

The helper copies and verifies a source snapshot before read-only mounting. Image:
`sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080`.
Sequential workers are offline, non-root, read-only, capability-dropped, limited to 1 CPU,
512 MiB memory and 64 processes, with bounded temporary storage. No Docker socket or target
installation is exposed. This reuses an existing local image, not a clean-machine build proof.
The pre-change archive and restore verification remain under the approved encrypted workspace.

## Next Gate

Repair memory/state next. The remaining family repairs precede separate producer adapters,
suppression policy, reporting integration and scoped public-target validation. Nothing here
changes earlier baseline findings, improves their historical results or authorizes a push.
