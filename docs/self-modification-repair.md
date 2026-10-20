# Self-Modification Draft Repair

20 October 2026. Family 5 of 7. **Development-only executable repair**, not an enabled
public-scanning profile, an autonomous-agent safety detector or a new benchmark result.

## Provenance and Scope

The student requested sequential repair under the established defensible-evidence policy.
Authorship of the original is student-declared; this repair and its finite expectations are
AI-assisted and have no independent outcome review. Both supplied Markdown parts were read.
The original and [inert extracted payload](../rule_candidates/submitted_2026_10_20/payloads/agent_self_modification_expanded.py.txt)
remain byte-identical. The original heading says 22, but its definitions contain **27 formal
IDs: 001-015 and 101-112**. Legacy `099` (parse error) and `MCP-001` are not extra active rules.

The repair separates **three active syntax conditions, ten inventory entries and fourteen
deferred entries**. Duplicate concepts remain identifiable in the catalog without emitting
duplicate alerts. Deferred can mean unsupported semantics or a redundant draft definition;
the boundary and `related_ids` explain which. These counts are not measured detection coverage.

| ID | Status | Repaired meaning |
|---|---|---|
| 001 | Condition, low review priority | Nonliteral assignment or `+=` to a `prompt`/`system_prompt` attribute |
| 002 | Inventory | Tool-generation/update API naming cue |
| 003 | Inventory | Memory/strategy/backend assignment naming cue |
| 004 | Inventory | Context-limit assignment or keyword syntax, not actual tokens |
| 005 | Inventory | Self-evaluation naming cue, not absence of human review |
| 006 | Inventory | Self/state persistence naming cue, not a verified write |
| 007 | Deferred | Model-output provenance and model-driven modification |
| 008 / 009 | Inventory | LangChain-family / AutoGen-family import declarations |
| 010 | Deferred | MCP self-modification; no assumed state/permission schema |
| 011 | Condition, medium review priority | Response-like direct expression passed to resolved builtin `eval`/`exec` |
| 012 | Inventory | Validation/approval hook naming, not proven authorization |
| 013 | Inventory | Version/diff/rollback naming, not proven integrity |
| 014 | Inventory | Update-named call lexically in a loop body, not an infinite loop |
| 015 | Deferred | Actual context overflow; setting syntax is already 004 |
| 101 | Condition, medium review priority | Memory-like direct expression passed to resolved builtin `eval`/`exec` |
| 102 / 103 / 104 | Deferred duplicates | Validation / drift / loop concepts already represented by 012 / 013 / 014 |
| 105 / 106 | Deferred duplicates | Overflow / injection concepts, not new independent detections |
| 107 | Deferred | Cross-framework mismatch requires actual API/version contracts |
| 108 / 109 | Deferred duplicates | Persistence / model-driven concepts already represented by 006 / 007 |
| 110 / 111 / 112 | Deferred duplicates | Framework concepts already represented by 008 / 009 / 010 |

The [machine-readable catalog](../src/agentsec_evidence/custom_rules/self_modification_catalog.py)
provides exact boundaries and a versioned hash. `SELF-MOD-011` overlaps `TOOL-EXEC-001/002`;
`SELF-MOD-101` overlaps `MEM-SEC-103` and `TOOL-EXEC-001`. Preserve original IDs and evidence
when later grouping reports; do not sum these as distinct vulnerabilities or new coverage.
A response-memory name can produce both 011 and 101 for one call; this is explicitly tested.

## Why the Draft Needed Repair

- Nonbreaking indentation and `_name_ == "_main_"` prevented normal Python execution.
- A constructor passed `file_line_range` although the dataclass did not define it.
- Scanning only calls whose names contain update/self/etc. missed assignments and ordinary
  `eval(response)`; nearby-line regex searches could associate unrelated code with a call.
- Regex-derived scores increased for validation/versioning and could treat controls as risk.
  Evidence-item counts were not calibrated confidence measurements.
- Nested evidence dictionaries made the proposed hash-based deduplication invalid.
- The CLI accepted a project directory but passed it to a file reader. Broad exception
  handling could convert scanner failures into low-severity findings or silently skip config.
- Framework mismatch used assumed framework lists. MCP state/permission schema and defaults
  lacked an established contract. Neither can support the original vulnerability claims.

The repair replaces these paths; it does not claim to make every original assertion valid.
There are no arbitrary scores, target imports, plugins, recursive public-project entry point,
model calls, guessed storage configuration or suppression erasure.

## Observable Conditions and Limits

The [detector](../src/agentsec_evidence/custom_rules/self_modification.py) uses the unchanged
shared lexical AST helpers. It resolves import aliases and conservatively refuses shadowed,
conditional or wildcard bindings. Python 3.13 signatures are checked: source is positional-only;
globals/locals may be keyword arguments and `closure` is exec-only. Unsupported/expanded calls
remain explicit limitations. The actual provisioned interpreter is 3.13.15; the online 3.13
documentation currently displays 3.13.16. See [Python builtins](https://docs.python.org/3.13/library/functions.html#eval).

Names such as response, reply, completion, memory, context, state and history are **heuristics**,
not taint sources. Direct attributes, subscript bases, string interpolation and addition are
inspected. Selectors alone, opaque function results, conditionals, assignments across statements
and interprocedural flow are not inferred. Import declarations do not prove that a framework
is installed, used or compatible. Dynamic monkeypatching and runtime resolution are not modeled.

For prompt assignment, a nonliteral right-hand side is the entire condition. A sanitizer call
still meets that syntax definition; no sanitizer failure is claimed. The receiver might not
be an agent, the value might be trusted, or an attribute descriptor might alter assignment.
Fixed literal values are controls, not proof of safety. Local prompt variables, reflective
`setattr`, subscript/destructuring writes and non-additive augmented writes are not classified
as the active prompt condition. Multiple prompt targets in one statement yield one condition
record. See [Python assignment semantics](https://docs.python.org/3.13/reference/simple_stmts.html#assignment-statements).

Loops record lexical placement only; nested function bodies and loop `else` blocks do not
inherit the enclosing loop-body observation. Even a two-iteration loop is inventory, not a
vulnerability. Lambda/comprehension bodies, annotations and type aliases are excluded.
Locations are one-based lines and zero-based UTF-8 byte columns, not character positions.
See [Python AST structures and locations](https://docs.python.org/3.13/library/ast.html).

## Worker and Evidence Contract

The [worker](../src/agentsec_evidence/custom_rules/self_modification_worker.py) uses contract
`self-modification-development-v1`, producer `student-self-modification-repaired`, version 1.0.0.
It validates the complete input view, request hash, membership, lengths and per-file hashes.
Selected files are rechecked after view validation; links/junctions and drift are refused.
Not-selected inputs stay visible. Non-Python selected files are unsupported with null findings.

Limits: 64 inventory files / 1 MiB aggregate, 256 KiB per input, 50,000 AST nodes, 1,000
observations per file, and 512 traversed view entries. Parse/resource errors retain null findings,
not an empty successful array. `complete` means the bounded file processing completed,
**not that all relevant security properties were analyzed**. Per-file and catalog limitations
remain visible. Exit 0 means no configured review threshold was hit; exit 1 means a threshold
hit; exit 2 means partial, empty or refused. Priorities are review ordering, not exploit severity.

Policy remains `research-only-no-suppressions-applied`. This is not a production repository-policy
view. Output contains locations, generic evidence kinds and source-bound IDs/hashes, not raw
snippets, identifier spellings or literal secrets. Input paths themselves can be sensitive.
Full local rehearsal bundles also contain source snapshots: they are not cleared for distribution.

## Verified Development Rehearsal

The [registry](../test_cases/development/self-modification-v1/cases.json) contains 60 independently
specified syntax assertions (independent of observed scanner output, **not independently reviewed
security labels**). It includes malformed input, controls, ordinary features and unknown cases.

The [finite rehearsal helper](../tools/verify_self_modification_repair.py) ran four treatments
in the existing pinned image, with unchanged tool/database/public-profile pins:

| Treatment | Selected files | Condition records | ID-bearing inventory observations | Execution / exit |
|---|---:|---:|---:|---|
| Full repeat 1 | 60 | 18 | 15 | Partial / 2 |
| Full repeat 2 | 60 | 18 | 15 | Partial / 2 |
| Valid only | 59 | 18 | 15 | Complete / 1 |
| Fixed/near-miss controls | 6 | 0 | 1 | Complete / 0 |

The two full native JSON reports are byte-identical:
`a389d4e0459e1c1d98b86df58dbb7307107b9b083dbfa0bb8d40f2dce881cbb7`.
One deliberately malformed case explains partial execution. **31 valid files retain explicit
limitations**, including three of the six controls; zero findings does not mean full coverage.
All finite assertions passed. There is no public accuracy estimate or runtime exploit result.

Isolation: pinned local image, no network, read-only root/source/input, nonroot user, all
capabilities dropped, no-new-privileges, 1 CPU, 512 MiB memory, 64 PIDs and 64 MiB noexec tmpfs.
No target installation or execution occurred. Preparation is outside measurement; retained
elapsed times are development timings, not a performance benchmark.

Local evidence (ignored by Git):
- `outputs/self_modification_repair_2026-10-20-final/verification.json`
- `outputs/self_modification_repair_2026-10-20-final/manifest.json`
- `outputs/self_modification_repair_2026-10-20_CLOSEOUT.json` and `.md` once the final audit passes.

Fresh focused Windows verification passed **713 tests** across all five repairs and import checks,
including 148 tests for this family. The separate closeout records the full offline Linux suite,
static checks, source stability and prior-bundle verification; do not infer a full-suite pass
from this focused count. Existing full mypy test-suite errors are recorded separately, not hidden.

Rehearsal requires the existing pinned validation image; it does not demonstrate an independent
clean-machine build. Choose a new output directory rather than overwriting evidence:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_self_modification_repair.py `
  --output outputs/self_modification_repair_new_attempt
```

## Next Gate

Repair agent orchestration, then agent-to-agent. Afterwards, add versioned producer adapters,
suppression/policy handling, controlled paired comparisons and separately admitted public
treatments. This family is not yet activated in ordinary CLI profiles, common reporting,
SARIF or HTML. No earlier scanner, shared helper, public treatment or sealed evidence was changed.
No commit/push is authorized by this repair.
