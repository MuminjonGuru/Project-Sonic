# Agent Orchestration Draft Repair

20 October 2026. Family 6 of 7. **Development-only, inventory-first repair.**
This family currently has **zero active security-condition or vulnerability rules**.
Successful processing and zero findings must not be described as secure orchestration.

## Provenance and Decision

The student requested the next sequential repair under the previously approved conservative
evidence policy. Original authorship is student-declared; the repair and finite expectations
are AI-assisted, without independent outcome review. Both Markdown parts were inspected.
All **22 formal IDs, ORG-001 through ORG-022**, remain registered. No 101-series definitions
exist in the supplied payload; none were invented. Legacy `ORG-099` and `ORG-MCP-001` remain
non-emitting metadata. The original Markdown and [extracted payload](../rule_candidates/submitted_2026_10_20/payloads/agent_orchestration_expanded.py.txt)
are unchanged.

The draft's features do not establish its vulnerability claims. Routing a task, sharing state,
calling another function, tuning a policy or importing a framework can all be ordinary behavior.
There is no supplied authorization/confidentiality policy, verified receiver type or model-output
provenance. Consequently, the repaired family preserves **nine inventory checks and thirteen
deferred/duplicate entries**, rather than manufacturing alert conditions.

This is useful for locating candidate review surfaces and describing supported observations.
It is **not** taint analysis, an agent dependency graph, a runtime call graph, an authorization
audit, an exploit detector or evidence of comprehensive orchestration coverage.

## Rule Interpretation

| ID | Status | Actual observation or reason |
|---|---|---|
| 001 | Inventory | Handoff-named call on an orchestrator-named receiver |
| 002 | Inventory | Routing-named call, including literal/nonliteral argument shapes |
| 003 | Inventory | State-operation naming such as update/get/persist/store |
| 004 | Inventory | Direct memory-like expression in a supported handoff payload keyword |
| 005 | Inventory | Routing-policy update, rewrite, tuning or self-evaluation naming |
| 006 | Deferred | Model-driven orchestration requires provenance and decision-flow evidence |
| 007 / 008 | Inventory | LangChain-family / AutoGen-family import declarations |
| 009 | Deferred | No assumed MCP state-store or permission schema |
| 010 | Inventory | Orchestration persistence naming; no verified storage write |
| 011 | Inventory | Immediate call or awaited call expression in an orchestration argument |
| 012 / 013 / 014 | Deferred duplicates | Handoff/routing/state claims already represented by 001/002/003 |
| 015 / 016 / 017 | Deferred duplicates | Leakage/policy/model claims already represented by 004/005/006 |
| 018 / 019 / 020 | Deferred duplicates | Framework concepts already represented by 007/008/009 |
| 021 / 022 | Deferred duplicates | Persistence/leakage concepts already represented by 010/004 |

The [catalog](../src/agentsec_evidence/custom_rules/orchestration_catalog.py) retains exact
boundaries and related IDs. No deferred ID emits an observation. Do not count duplicate IDs
as extra coverage or an inventory record as a vulnerability.

## Repair Rationale

- Replaced nonbreaking indentation, invalid `_future_` import and `_name_` entrypoint.
- Removed a constructor argument absent from its dataclass and invalid hashing of nested
  evidence dictionaries. Removed alphabetical severity ordering and uncalibrated scoring.
- Replaced nearby-line regex matching with specific AST nodes, avoiding comment/string hits
  and unrelated nearby calls. The draft's Unicode-arrow and `${...}` patterns were not proof
  of valid Python dataflow.
- Removed guessed MCP state/storage defaults and silent configuration parse failure.
- Replaced directory-as-file reading and unrestricted traversal with the established exact-view
  worker. Original parse failures no longer become low-severity findings.
- Removed unused purported controls such as max handoffs and orchestrator-type scoring.
  The repair does not claim handoff-count enforcement or safe routing.

## Supported Syntax

The [inventory module](../src/agentsec_evidence/custom_rules/orchestration.py) recognizes
`orchestrator` or a simple attribute chain ending `.orchestrator` as a **spelling heuristic**.
Even a non-agent object named this way is inventoried, with an explicit unresolved-API
limitation. No receiver type, effective method or installed framework is inferred.

The named handoff methods are send/forward/handoff/share; routing methods are
route/select/dispatch/choose. State-operation shapes require `.state` below the named receiver.
Policy and persistence names are finite lists in the module. Other candidate receiver/method
shapes are unsupported observations. Object aliases, dynamically returned receivers and
arbitrary framework call APIs are not resolved.

Argument records preserve positional/keyword ordinal, literal/nonliteral/expanded syntax and
immediate-call shape. They omit literal values and arbitrary keyword names. Unknown signatures
mean positional arguments are **not** interpreted as particular payload parameters.
Expanded or duplicate keyword arguments retain ambiguity and prevent memory-payload attribution.
Python's call rules distinguish argument expressions, keyword binding and expansion; the repair
does not attempt to prove a call will succeed. [Python call semantics](https://docs.python.org/3.13/reference/expressions.html#calls)

ORG-004 inspects only supported payload keywords: data, prompt, context, memory and state.
Name/attribute heuristics, subscript bases, explicit container values, string interpolation and
addition are recognized. Dictionary keys, recipient arguments, selector-only references,
conditional branches and opaque call results are not treated as direct memory flow.
The result does not establish actual memory content or confidentiality. Opaque transformations
remain explicit limitations, including when another direct sibling expression is visible.

ORG-011 records immediate argument calls, not function references or calls buried in a container
or lambda body. Multiple nested argument expressions produce one observation for their parent
call, not several presumed handoffs. Persistence-named calls do not use this orchestration
nesting classification. This is lexical structure only.

Framework imports are declarations, even inside unexecuted branches. They are not installed
versions, framework-specific mutation support or runtime usage. Relative/lookalike imports do
not qualify. Lambda/comprehension bodies, annotations and type aliases are excluded; function
defaults and class-base expressions are inspected as syntax. Locations use one-based lines and
zero-based UTF-8 byte columns. [Python AST reference](https://docs.python.org/3.13/library/ast.html)

## Worker and Evidence Contract

The [worker](../src/agentsec_evidence/custom_rules/orchestration_worker.py) emits
`orchestration-development-v1`, producer `student-orchestration-repaired`, version 1.0.0, and
capability **`inventory-only-no-security-verdict`**. The file schema prohibits a nonempty
findings array. An analyzed file returns `[]`; malformed/unsupported/failed files return null.
Inventory observations have source-bound IDs, locations and hashes. Full input accounting,
request hashes, exact membership, lengths and post-validation file hashes are checked.

Limits: 64 files / 1 MiB aggregate, 256 KiB per file, 50,000 AST nodes, 1,000 observations per
file, 128 top-level call arguments and 512 traversed view entries. Links, junctions, drift and
resource excesses are refused or failed, never truncated into success.

`complete` means the bounded inventory processing completed, not security coverage.
Exit 2 means partial/empty/refused. Exit 0 means completed inventory, **not a clean security
scan**; no review threshold can generate exit 1 because this version has no active conditions.
The accepted threshold option preserves worker invocation consistency but does not turn
inventory into findings. Suppressions are not applied; the report labels the research-only policy.

There is no target execution/import, installation, model call, storage access or network request.
Reports omit source snippets, variable spellings and literal secrets, but input paths can still
be sensitive. Local bundles include full authored inputs and implementation snapshots and are
not automatically distribution-cleared.

## Development Verification

The [60-case registry](../test_cases/development/orchestration-v1/cases.json) was authored before
native execution. It tests declared syntax behavior, not independent vulnerability labels.
The [rehearsal helper](../tools/verify_orchestration_repair.py) produced:

| Treatment | Files | Inventory observations with IDs | Findings | Execution / exit |
|---|---:|---:|---:|---|
| Full repeat 1 | 60 | 56 | 0 | Partial / 2 |
| Full repeat 2 | 60 | 56 | 0 | Partial / 2 |
| Valid only | 59 | 56 | 0 | Complete / 0 |
| Fixed/ordinary controls | 6 | 3 | 0 | Complete / 0 |

The helper names the last treatment `corrected-controls`; it is a fixed/ordinary syntax contrast,
not a claim that vulnerabilities were remediated. One intentionally malformed case explains
partial processing. Forty-six valid files have explicit limitations, including three controls.
The two full reports are byte-identical:
`9b4f8be300d616000b4241f33e93df8e1c83c50f52d8094d8ebe4f2a3431692b`.

Runs used the existing pinned offline image with read-only root/input/source, nonroot user,
all capabilities dropped, no-new-privileges, 1 CPU, 512 MiB, 64 PIDs and a 64 MiB noexec tmpfs.
No public target or previous scanner/profile was changed. Timings are retained as development
execution evidence, not a performance comparison.

Fresh focused Windows checks passed **840 tests**, including **127** for this family.
The separate final closeout records full offline Linux regression, static checks, source
stability, verified backup/restore and unchanged prior evidence. It is created only after those
checks pass; the focused count alone is not a full-suite result.

Local evidence, ignored by Git:
- `outputs/orchestration_repair_2026-10-20-final/verification.json`
- `outputs/orchestration_repair_2026-10-20-final/manifest.json`
- `outputs/orchestration_repair_2026-10-20_CLOSEOUT.json` and `.md` after audit completion.

Replay requires the existing pinned validation image, not a demonstrated clean-machine rebuild.
Use a fresh output directory:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_orchestration_repair.py `
  --output outputs/orchestration_repair_new_attempt
```

## Next

Repair agent-to-agent, then add separately versioned reporting adapters and policy/suppression
tests before admitted public comparisons. Inventory must remain separate from condition findings
in CLI/SARIF/HTML reporting. A future orchestration security rule needs an explicit supported
framework/API and observable policy violation; ordinary routing must not be relabeled unsafe.
No common-report activation, public scanning, commit or push is part of this repair.
