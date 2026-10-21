# Initial Rule Import Review

Date: 20 October 2026. Scope: extraction, lexical inventory, source inspection and isolated
Python syntax diagnostics. This is not a full security audit, rule-accuracy benchmark,
independent review or approval for runtime use. Original student code is preserved.

## Findings Requiring Work Before Activation

1. **All seven exact Python payloads fail parsing.** Six first fail on U+00A0 non-breaking-space
   indentation; the memory payload fails in a malformed quoting context. An isolated diagnostic
   replacing only U+00A0 with ASCII spaces in memory lets six parse, but the memory payload still
   fails. No source bytes were repaired. Parsing the diagnostic variants does not prove they
   import or work. Memory starts with a triple quote followed by code and another docstring;
   its multipart boundary needs deliberate repair, not a blanket punctuation replacement.
2. **Python runtime names are damaged.** Five syntactically parsed diagnostic variants contain
   `from _future_ import annotations` instead of `__future__`. Every scanner has an
   `if _name_ == "_main_"` guard. The memory draft also contains the misspelled import text,
   but its syntax failure prevents treating it as a parsed import. These issues must be
   corrected in working copies before execution can meaningfully test detection behavior.
3. **Severity filtering is not an ordered severity policy.** In
   [tool_execution.py.txt](payloads/tool_execution.py.txt), line 548 compares strings with
   `f.severity.value >= min_severity.value`. The differential code also compares severity
   strings. Alphabetic order does not implement critical > high > medium > low. Fix and test
   every threshold and escalation direction rather than inheriting these expressions.
4. **Rule loading can execute arbitrary Python.** The same file, line 455, calls
   `spec.loader.exec_module(mod)` for an additional rule file. Do not expose this through
   repository-selected rules. Only reviewed, pinned scanner code may execute in the isolated
   worker; target-supplied code/configuration is data, not a trusted plugin.
5. **Error state is mixed with vulnerability findings or silently omitted.** The tool scanner,
   line 254, catches any exception and emits `TOOL-EXEC-099` as a low-severity finding. The
   memory configuration reader, line 941, catches exceptions and continues. Execution,
   parsing and coverage failures need separate machine-readable states and must not become
   ordinary vulnerabilities or successful no-finding scans.
6. **Evidence and scoring claims need condition-level validation.** The tool scanner uses
   regex matches against a multi-line snippet to label user-input conditions; this alone is
   not source-to-sink proof. Hard-coded risk scores and framework/LLM keyword heuristics in
   the drafts are authored heuristics, not calibrated measurements. Do not copy their
   "production-ready" wording, 0-100 scores or remediation assertions into a validated claim.
7. **The memory implementation defines `compute_risk_score` twice**, at extracted lines 430
   and 955. Once syntax is repaired, normal module execution would use the later definition.
   Reconcile intended behavior explicitly instead of silently choosing or merging them.
8. **Standalone traversal and serialization are not the platform integration contract.**
   The scripts use their own `rglob`, config readers, dataclasses, CLI options and output
   handling. They need bounded admitted-input handling, dependency audit (including YAML
   parsing where used), normalized evidence and replay/coverage tests before public-target use.

These are directly observed blockers and review leads, not an exhaustive defect list.
No target repository, scanner imports, user-code entrypoints or external plugins were run.

## Inventory Correction

The earlier chat rows add to 130 rules and 38 categories, not the stated 116 and 34.
The actual submitted Python text differs again:

| Python payload | Lines including blanks/comments | Literal `id` entries | Category enum members |
|---|---:|---:|---:|
| Tool execution | 665 | 5 | 4 |
| Network/data transfer | 782 | 18 | 6 |
| Filesystem access | 819 | 12 | 8 |
| Memory/state | 1,123 | 18 | 7 |
| Self-modification | 1,202 | 27 | 8 |
| Orchestration | 1,121 | 22 | 5 |
| Agent-to-agent | 1,104 | 26 | 5 |
| **Total** | **6,816** | **128** | **43** |

All 128 literal ID strings are distinct across the seven Python payloads. This lexical count
does not establish how many rules are executable, invoked, reachable, correct or independent.
Runtime-emitted IDs, computed IDs and source-code strings require separate reconciliation.
The 43 figure sums per-scanner enum members; it is not 43 unique security concepts.

The separate YAML payload has 171 lines and five `TOOL-EXEC` rule IDs, overlapping the five
Python IDs. It is an alternative representation, not five additional distinct rules.
It was preserved but not YAML-parsed or checked for equivalence to the Python definitions.
No submitted detector has been admitted to the active profile by this review.

## Verification Performed

- Eight pre-change files (seven originals plus the development `.gitignore`) were archived
  and restored; restored hashes matched. Archive protection uses the existing disk encryption.
- The extraction helper passed 13 focused tests on each of two runs: byte preservation/non-execution, source hash
  rejection, invalid/overlapping spans, path/extension restrictions, fence exclusion, no overwrite,
  tamper/extra-file rejection, lexical inventory and ordered multipart assembly.
- The seven Python payloads received AST syntax diagnostics in the existing pinned image
  `sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080`.
  Network was disabled, inputs read-only, capabilities dropped, no-new-privileges set,
  non-root user selected, with 1 CPU, 256 MiB RAM and 64 PIDs. The container was removed.
- The worker parsed text only, without importing or executing candidate code. The optional
  whitespace diagnostic changed in-memory strings only and did not save corrected scripts.
- Exact import replay verifies every selected source span and the generated payload/manifest.
  This is recorded consistency, not independent attestation.
- Existing product source, scanner profiles, upstream rules and historical results were not
  changed by this import. No full application regression or detector behavior suite was run.
- Repository `ruff check src tests tools` passed; format verification passed on 229 files;
  `git diff --check` passed. Git ignore checks confirmed `new_rules/` exclusion at root/nested
  locations inside the development repository. No original draft is tracked by that repository.

Local receipts, not Git-distributed originals:

- `workspace/rule-import-2026-10-20/tests-01.xml`
- `workspace/rule-import-2026-10-20/tests-02.xml`
- `workspace/rule-import-2026-10-20/syntax-inspection.json`
- `workspace/rule-import-2026-10-20/syntax-invocation.json`
- `workspace/rule-import-2026-10-20/inspect_syntax.py`
- `../Backups/rule-draft-import-2026-10-20/verification.json`

## Recommended Next Increment

Use a separate working implementation, starting with tool execution: repair transport/runtime
defects, replace unsafe plugin/traversal paths, reconcile the five supplied rules, and define
observable conditions and finite tests. Reuse the existing orchestrator and evidence model
instead of starting seven unrelated production CLIs. Keep other families in the inventory;
admit each only when its execution, condition and negative-control tests pass. Public repository
testing remains the intended next evaluation stage, not a substitute for these controls.
