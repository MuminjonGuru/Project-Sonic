# Request-URL Source-Condition Contrast

Approved finite development scope, 18 October 2026. This increment measures one existing
Agent Audit claim without changing the analyzer, adding a detector or admitting a public target.

## Question and Reference

Does the pinned analyzer's `AGENT-026` unsanitized-tool-input report distinguish a caller-supplied
initial request URL from a fixed or locally restricted destination?

The retained public pilot motivated the question: a report referred to a parameterless helper
using a fixed URL. That observation is a lead, not a complete recall/precision study or proof
of root cause in upstream code. The new cases are deliberately reduced development contrasts,
not copies of the public repository or held-out samples.

The independent source condition is a directly decorated tool passing its string URL parameter
directly to `requests.get` without a fixed destination restriction. The fixture registry states
the condition and expected facts before scanner execution. Student approval covers these four
conditions; exact text/expectations are AI-authored and not independently adjudicated.

| Case ID | Source fact | Expected named condition |
|---|---|---|
| `url-caller-tool` | Direct caller URL parameter reaches `requests.get` | Present |
| `url-fixed-helper` | Parameterless, undecorated helper; fixed URL variable | Absent |
| `url-fixed-tool` | Parameterless decorated tool; fixed URL variable | Absent |
| `url-allowlisted-tool` | Tool selects a key in a local fixed URL mapping | Absent |

Absent here means absence of this condition, not safe software. Redirects, host resolution,
endpoint integrity, effective egress, runtime invocation and exploitability are not tested.
The restricted destination example is not a complete SSRF mitigation prescription.

## Execution and Evidence

`agents/url_contrast.py` validates the separate byte-pinned registry. The existing
`orchestration/agent_pipeline.py` selects this registry only for its four admitted IDs and records
the distinct `agent-url-contrast-development-v1` source revision. All original thirteen IDs,
case bytes, historical schemas, tool/profile pins and benchmark admissions remain unchanged.
The existing agent benchmark runner does not automatically acquire these four new cases.

```powershell
agentsec-evidence scan agent-audit url-fixed-helper --json
.venv/Scripts/python.exe -X utf8 tools/verify_agent_url_contrast.py `
  --output workspace/url-contrast-new-attempt --repetitions 2
```

The second command freezes fixture, profile, tool, helper and implementation hashes before
sequential execution. Each run retains input validation, native stdout/stderr, invocation,
normalized findings, SARIF and bundle hashes through the existing pipeline. It writes start and
finish receipts, an evidence-linked CSV/table, per-case semantic repeatability and a common
report. New destination only; no silent retry or general benchmark-resume claim.

Execution uses the existing pinned offline syntax worker and Agent Audit 0.20.0 image, read-only
targets, no network, bounded resources and no target imports, installations or calls. Even the
positive request is inert source text, never a live request. No paid service is used.

## Interpretation

- A named rule report with the condition present supports this exact source-pattern observation.
- A named rule report with the condition absent is a claim/condition discrepancy to investigate.
- No named report is recorded as such, not successful complete analysis or a safety verdict.
- Failed/unparsed runs are not assessable and never become negative cases.
- Other rule reports remain retained and separately reviewable; they are not discarded.
- Repeats measure stability within one source family, not additional independent examples.
- Native severity, confidence, CWE and remediation stay assertions; this increment does not
  endorse them, calculate public accuracy or establish four vulnerabilities.

The matrix is an experimental diagnostic, not a general source-code classifier. Upstream rule
failure is an outcome and does not trigger profile tuning. Any refinement or new treatment needs
a separately versioned decision with the original evidence preserved.

## Deadline Boundary

The student requires all development and testing to finish by 25 October 2026. Paper writing and
charts use retained data during the following 21 days. This increment prioritizes useful security
evidence before delivery polish; routine regression and source/evidence integrity remain required.
