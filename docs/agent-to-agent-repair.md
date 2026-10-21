# Agent-to-Agent Draft Repair

20 October 2026. **Family 7 of 7; development-only, inventory-first.**
This version has **zero active security-condition or vulnerability rules**.
Zero findings cannot be interpreted as safe agent communication.

## Provenance and Scope

The student requested continuation under the approved defensible-evidence policy.
Original authorship is student-declared. Repair decisions and controlled expectations
are AI-assisted, not independently reviewed labels or academic approval.

All three Markdown parts and the [immutable extracted payload](../rule_candidates/submitted_2026_10_20/payloads/agent_to_agent_expanded.py.txt)
were reviewed. There are **26 formal IDs: A2A-001 through 018 and 101 through 108**.
All remain registered: **10 inventory entries, 16 deferred/duplicate concepts**.
Legacy A2A-099 (parse diagnostic) and A2A-MCP-001 are non-emitting metadata.
Originals, six previous repairs and historical profiles remain unchanged.

Calls, trust methods, signing and property assignments do not establish impersonation,
unauthorized grants, leakage or temporal authorization drift. Inventory helps locate
review surfaces; it is not a security verdict. **A2A means generic agent-to-agent naming
inventory here, not support for the Agent2Agent protocol**, transport or message schemas.

## Rule Interpretation

| ID | Status | Actual observation or unresolved requirement |
|---|---|---|
| 001 | Inventory | Agent-like call/route/forward/select syntax |
| 002 | Inventory | Prompt-update, rewrite-system-prompt or impersonate naming |
| 003 | Inventory | Authorize/trust/trust-chain operation naming |
| 004 | Inventory | Share-memory naming or direct state/context/memory/input property copy |
| 005 | Inventory | Sign/verify naming, not a defective security control |
| 006 | Deferred | Model-driven decisions require provenance and decision-flow evidence |
| 007 / 008 | Inventory | LangChain-family / AutoGen-family import declarations |
| 009 | Deferred | No guessed MCP trust/state-sharing schema |
| 010 | Inventory | Exact save_a2a / persist_a2a / write_a2a_config naming |
| 011 / 012 | Deferred duplicates | Identity/trust claims add no model-origin evidence |
| 013 / 014 | Deferred duplicates | State and signing/authorization concepts already represented |
| 015 / 016 / 017 / 018 | Deferred duplicates | Call, identity, trust and state concepts |
| 101 | Inventory | Immediate agent-like call/awaited call within an agent-like call argument |
| 102 / 103 / 104 | Deferred duplicates | Model-driven identity, trust and state claims |
| 105 | Inventory | Direct matching role/permissions property-copy syntax |
| 106 / 107 / 108 | Deferred duplicates | Call, identity and trust concepts |

The [catalog](../src/agentsec_evidence/custom_rules/agent_to_agent_catalog.py) retains
boundaries and related IDs. Authorize uses 003, sign/verify use 005; duplicate concepts
never emit extra records.

## Repairs and Syntax Boundaries

The [module](../src/agentsec_evidence/custom_rules/agent_to_agent.py) replaces invalid
`_future_`, nonbreaking indentation, incorrect `_name_` entrypoint, an absent dataclass
argument and unhashable evidence deduplication. It removes unvalidated scores,
alphabetical severity ordering, unused trust/max-agent controls, nearby-line regex
association, directory-as-file scanning and silent parse failure. Guessed MCP defaults
and Unicode-arrow text are not treated as real dataflow.

Receiver recognition is lexical: `agent`, `agent1`, `agent2`, etc., or a simple attribute
chain ending in those spellings. `agent0`, `agent02`, factory results, object aliases and
arbitrary APIs are not resolved. Even a non-agent object so named yields inventory with
an explicit unresolved-API limitation. No type or principal identity is established.

Argument records preserve ordinal and literal/nonliteral/expanded/immediate-call shapes,
not values or arbitrary keyword names. Expanded or duplicate keywords retain ambiguity.
Positional parameters receive no security-role interpretation. Nonliteral input is not
proof of model control or risk.

101 requires immediate call/awaited-call syntax with a recognized receiver and
call/route/forward/select method inside another such call. Multiple arguments produce
one parent nesting observation. Helper calls, attributes, lambdas, containers,
conditionals and starred expansions are not that immediate relationship. Their inner
expressions may have separate call inventory. No execution or trust graph follows.

Property-copy inventory requires direct agent-like attributes: state/context/memory/input
uses 004; role-to-role or permissions-to-permissions uses 105. Same-spelled receivers are
not presumed distinct. Unpacking, augmented updates, calls and conditional sources remain
unsupported flow. Actual values, descriptor effects and effective privileges are unknown.

Imports are declarations, including unreachable branches, not installed/runtime support.
Relative/lookalike imports do not qualify. Lambda/comprehension bodies, annotations and
type aliases are excluded; defaults and class bases are inspected as syntax.
See the [Python AST reference](https://docs.python.org/3.13/library/ast.html) and
[call semantics](https://docs.python.org/3.13/reference/expressions.html#calls).
Those web pages currently render 3.13.16; the pinned runtime is 3.13.15.

## Worker and Safety

The [worker](../src/agentsec_evidence/custom_rules/agent_to_agent_worker.py) emits
`agent-to-agent-development-v1`, producer `student-agent-to-agent-repaired`, version 1.0.0,
capability `inventory-only-no-security-verdict`. The schema rejects nonempty findings.
Analyzed files have `[]`; malformed/unsupported/failed files have null. Records carry
source-bound IDs, hashes and one-based lines/zero-based UTF-8 byte columns.

Exact request, membership, hashes, lengths and post-validation bytes are checked.
Limits: 64 files / 1 MiB aggregate, 256 KiB per file, 50,000 AST nodes,
1,000 observations per file, 128 top-level arguments and 512 view entries.
Links, junctions, drift and resource excesses are refused/failed, never silently truncated.

Exit 0 means completed inventory, **not a clean security scan**. Exit 2 means partial,
empty or refused. No threshold produces exit 1 in this version. Suppressions are not
applied; policy is `research-only-no-suppressions-applied`.

No target execution/import, installation, model call, live storage or network occurs.
Reports omit snippets and literal secrets; paths can still be sensitive. Bundles retain
authored inputs and source snapshots and are not automatically distribution-cleared.

## Development Verification

The [60-case registry](../test_cases/development/agent-to-agent-v1/cases.json) was authored
before native execution. It tests syntax contracts, not independent vulnerability labels.
The [rehearsal helper](../tools/verify_agent_to_agent_repair.py) recorded:

| Treatment | Files | ID inventory observations | Findings | State / exit |
|---|---:|---:|---:|---|
| Full repeat 1 | 60 | 49 | 0 | Partial / 2 |
| Full repeat 2 | 60 | 49 | 0 | Partial / 2 |
| Valid only | 59 | 49 | 0 | Complete / 0 |
| Fixed/ordinary controls | 6 | 3 | 0 | Complete / 0 |

One deliberate malformed input explains partial processing. Forty-eight valid files have
explicit limitations, including three controls. The helper label `corrected-controls`
means a fixed/ordinary contrast here, not verified remediation. The full native reports
are byte-identical:
`2d09d87dd6fe168bfd43cfeba9a560cb0f9543ae957109905b5598b4c758cb47`.

Runs used the existing pinned offline image, read-only root/input/source, nonroot user,
cap-drop ALL, no-new-privileges, 1 CPU, 512 MiB, 64 PIDs and 64 MiB noexec tmpfs.
Timings are retained as development evidence, not performance-comparison results.

**975 focused Windows tests passed, including 135 family tests.** The separate closeout
is created only after full Linux regression, static checks, source stability and
evidence/backup audits pass. This is not independent-machine reproduction.

Local evidence, ignored by Git:
- `outputs/agent_to_agent_repair_2026-10-20-final/verification.json`
- `outputs/agent_to_agent_repair_2026-10-20-final/manifest.json`
- `outputs/agent_to_agent_repair_2026-10-20_CLOSEOUT.json` and `.md` after audit.

Repeat with the existing pinned image and a new output directory:

```powershell
.venv/Scripts/python.exe -X utf8 tools/verify_agent_to_agent_repair.py `
  --output outputs/agent_to_agent_repair_new_attempt
```

## Next Gate

All seven families have repaired development modules, **not complete product integration
or comprehensive agent-security coverage**. Next, define the combined reporting contract:
separate condition findings, inventory, deferred checks, refusals and limitations;
preserve overlaps without counting them as independent vulnerabilities. Add policy,
suppression and report/HTML tests before a versioned combined public treatment.
Real authorization checks require supported APIs and observable policy violations.

No ordinary CLI profile, common-report, SARIF or HTML activation, new public scan,
commit or push is included in this repair.
