# Tool-Execution Repair, Version 1

Date: 20 October 2026. Scope: the first of seven student-submitted scanner drafts.

## Status and Authority

The student approved retaining the five IDs while narrowing claims to defensible observations,
recording ordinary tool registration as inventory, and leaving MCP configuration analysis to the
existing analyzer. The submitted Markdown is student-declared original code. The repair, tests
and contracts are AI-assisted engineering work; this is not independent outcome review.

The repaired detector is in the installable development package:

- [Detector and five-rule catalog](../src/agentsec_evidence/custom_rules/tool_execution.py).
- [Bounded JSON worker](../src/agentsec_evidence/custom_rules/tool_execution_worker.py).
- [Controlled expectations](../test_cases/development/tool-execution-v1/cases.json).
- [Rule tests](../tests/unit/test_tool_execution_rules.py) and
  [worker tests](../tests/unit/test_tool_execution_worker.py).
- [Docker rehearsal](../tools/verify_tool_execution_repair.py).

**Integration level: callable package module and isolated development worker.** It is not enabled
in `agentsec-evidence` scan profiles, common-report/SARIF/HTML adapters, historical benchmarks or
public pilots. Those require an explicitly versioned producer/profile increment. The old
Semgrep, Agent Audit, MCP and dependency results are unchanged. The other six drafts are untouched.
Five IDs are not five confirmed vulnerability classes or comprehensive agent-security coverage.

## Rule Contracts

| ID | Version 1 observation | Does not establish |
|---|---|---|
| TOOL-EXEC-001 | A syntactically resolved builtin `eval`/`exec` call has a nonliteral first argument | User control, lack of validation, reachability, or exploitability |
| TOOL-EXEC-002 | That argument has one of the three explicitly supported response-access shapes | Actual model origin or an LLM-to-execution dataflow |
| TOOL-EXEC-003 | An explicitly imported shell API, or a supported subprocess call with literal `shell=True` | Injection, hostile input, or that a fixed command is malicious |
| TOOL-EXEC-004 | A supported tool-decorated function passes its unreassigned parameter name directly to builtin `eval`/`exec` | A cross-function path, attacker control, absent guards, or an invocation at runtime |
| TOOL-EXEC-005 | A supported dynamic-import call has a nonliteral module-name argument | A malicious module, an eval chain, or reachable code execution |

Supported response shapes: `response.choices[integer].message.content`, `llm_result.output`,
and `agent.response`. These are explicitly heuristic syntax observations, not provenance.

Supported decorator imports: `langchain_core.tools.tool` and `langchain.tools.tool`, including
unambiguous import aliases, bare decorators and decorator calls. Normal registrations are
inventory, not findings. An arbitrary variable named `tools` does not prove a registration.
FastMCP and other frameworks are not inferred from similar names.

Supported subprocess calls: `run`, `Popen`, `call`, `check_call`, `check_output`.
Explicit shell APIs: `os.system`, `os.popen`, `subprocess.getoutput`, `subprocess.getstatusoutput`.
Dynamic imports: builtin `__import__` and `importlib.import_module`.

High/medium labels are provisional rule-authored triage priorities, not CVSS, calibrated
confidence, or severity of a verified vulnerability. Overlapping IDs are retained individually.
A single tool parameter-to-eval call can yield 001 and 004; do not sum them as two vulnerabilities.

## Changes from the Submitted Draft

The immutable source is [the extracted payload](../rule_candidates/submitted_2026_10_20/payloads/tool_execution.py.txt).
The original YAML payload remains historical and **is not a runtime rule source** for version 1.

| Draft problem | Repair |
|---|---|
| Nonbreaking indentation, `_future_` and `_name_` transport defects | Valid Python package module and tested module entry point |
| CLI context omitted the five defaults | Fixed, explicit catalog; no optional plugin injection |
| Regex on surrounding lines caused adjacent-call/comment matches | AST call/argument predicates with exact source ranges |
| Variable names were labeled user input or LLM origin | Bounded syntactic observations; unknown provenance stays unknown |
| Claimed eval sanitizers included `eval(ast.literal_eval(...))` | No safety exemption or automatic downgrade for an outer eval/exec |
| 004 did not establish its advertised tool-parameter condition | Supported decorator plus direct, unreassigned parameter reference only |
| 005 had `_import_` and an unproven execution-chain claim | Actual `__import__`/`import_module` argument condition |
| All findings received CWE-95 and unrelated references | No automatic taxonomy assignment; rule-specific review is still required |
| Severity sorted alphabetically, inconsistent JSON exit behavior | Explicit ordinal policy; JSON retained before exit 0/1/2 |
| Parser errors were low-severity security alerts | Separate malformed/failed states with `findings: null` |
| Normal registrations emitted risk alerts | Supported registrations recorded as inventory |
| Python plugin files executed through `exec_module` | Arbitrary Python/YAML/JSON rule loading removed |
| Unsupported ad hoc MCP parser and character-offset "line" | Removed from this detector; existing MCP analyzer remains separate |
| Arbitrary risk score and rule-ID-only historical diff | Removed; native findings remain separate and source-bound |
| Unbounded recursive host scan and unstable Python `hash` IDs | Explicit bounded inventory in an offline worker; SHA-256 record identities |

001's draft critical label becomes high; 003's high becomes medium; 004's medium becomes high
for the narrower direct tool-parameter observation. These are design choices, not measured
severity improvements. No old finding is relabeled.

## Scope and Failure Accounting

Import resolution is conservative and lexical. Reassignments, parameters shadowing builtins,
conditional imports, wildcard imports, `global`/`nonlocal`, and ambiguous bindings do not justify
claiming a known sink. Relevant unresolved calls are recorded as limitations. Imported module
names are not verified runtime objects: local module substitution and monkey-patching remain
outside scope.

Lambda and comprehension bodies are explicitly unsupported. There is no analysis of annotations,
assignment aliases, wrappers, arbitrary decorators, computed attributes, interprocedural or
cross-file flow, branch reachability, sanitization, model behavior, or effective permissions.
Code in unreachable branches can still produce a syntax observation. Literal arguments are
inventory only, not proof of safety. Nonliteral shell flags and argument expansion are unknown.
File parsing completes only the bounded checks, not general Python or security coverage.

The request uses the existing `agent-input-request-v1` inventory contract. The worker requires
exact membership and bytes, no symlinks/junctions, at most 512 filesystem entries, 64 files,
1 MiB aggregate input, 256 KiB per file, 50,000 AST nodes per parsed file, and 1,000 combined
findings/inventory/limitation records per analyzed file. Resource failures do not return a
truncated "successful" finding list. AST parsing never imports or executes target code.

Selected files have `analyzed`, `malformed`, `unsupported` or `failed` states. Unselected files
remain in the inventory and `not_selected` list. Empty selection is not successful analysis.
`execution_state: complete` means the selected files completed these bounded checks, not that
all constructs were supported or the target is safe. `limitations_observed` remains visible.

The worker is research-only: it does not read `.gitignore`, target policy files or inline
suppression instructions. A `# noaudit` marker does not suppress its findings. Policy-view
support must be separately designed; do not describe this as honoring repository suppressions.

Only JSON output is supported. Exit 0 means complete processing without a threshold breach
(or no threshold requested), exit 1 means the requested priority threshold was met, and exit 2
means refusal, partial/empty processing or failure. Findings and processing status remain distinct.
Ranges explicitly use one-based lines and zero-based UTF-8 byte columns, not display columns.
Evidence snippets are capped at 512 characters with a truncation flag.

## Controlled Verification

The 34-case development registry contains positive, corrected, near-miss, malformed, shadowing,
unknown-argument and suppression-marker cases. Expected IDs are specified from the bounded
syntax conditions, not generated from scanner output. These are AI-authored engineering
expectations, not independent labels, held-out evaluation or proof of precision/recall.

The rehearsal uses the existing pinned Linux validator image, Python 3.13.15, no network,
nonroot UID/GID, read-only source/target/request mounts, dropped capabilities, no-new-privileges,
1 CPU, 512 MiB memory, 64 PIDs, a 64 MiB temporary filesystem and a 90-second invocation limit.
The copied implementation, exact input bytes, request, image inspection, commands, stdout,
stderr, process codes/timings and SHA-256 manifest are retained outside Git.

Run from the development checkout, with Docker Desktop's Linux engine ready:

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest `
  tests/unit/test_tool_execution_rules.py tests/unit/test_tool_execution_worker.py

.venv/Scripts/python.exe -X utf8 tools/verify_tool_execution_repair.py `
  --output outputs/tool_execution_repair_NEW_ATTEMPT
```

The output directory must be new and below `outputs`. No target installation, target execution,
database/tool refresh or network model call occurs. Existing native evidence is never overwritten.

The first rehearsal produced 23 rule observations on 33 parseable cases, with one malformed
case making both full runs partial. Their raw JSON was identical. The separate valid-only
treatment exited 1 at a high threshold; four corrected controls exited 0 without findings.
Five valid cases retained explicit unresolved/unsupported constructs. These are finite expected
observations, not 23 vulnerabilities or 34 independent research samples.

See the local final verification receipt under
`outputs/tool_execution_repair_2026-10-20-final/verification.json` and the closeout record under
`outputs/tool_execution_repair_2026-10-20_CLOSEOUT.md` for final-source test counts.

Closeout: 116 focused Windows tests (103 new tests plus 13 import-preservation tests) and
1,687 full offline Linux tests passed without failures or skips. All 193 final evidence files
and 135 implementation/snapshot files verified. Ruff and formatting passed; application source,
new tests and the rehearsal helper passed mypy. The wider `mypy src tests` check still reports
11 pre-existing errors in the untouched `test_rule_draft_import.py` and `test_qdrant_pilot.py`.
Those are separate test-typing cleanup, not a passing repository-wide type check.

## References and Next Gate

Python's [eval/exec documentation](https://docs.python.org/3.13/library/functions.html#eval)
supports treating dynamic evaluation cautiously, not accepting a variable named `safe_globals`
as a security boundary. Its [subprocess security considerations](https://docs.python.org/3.13/library/subprocess.html#security-considerations)
distinguish shell invocation from ordinary subprocess use. The
[AST documentation](https://docs.python.org/3.13/library/ast.html#ast.AST.col_offset) defines the
UTF-8 byte offsets retained here. Accessed 20 October 2026; the online 3.13 documentation banner
reported 3.13.16, while our actual interpreter/image remains pinned to 3.13.15.

Next file: network/data-transfer draft, with the same preserved-source, explicit-contract,
repair, controlled-test and isolated-run sequence. Before any new public scanning, admit the
custom producer's adapter/profile, preserve old baselines, and separately justify repository
selection and comparison metrics. Do not infer broad readiness from this first repair.
