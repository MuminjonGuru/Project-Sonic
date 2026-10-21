# Student Rule Submission: 20 October 2026

Status: **imported for integration review; inactive and unvalidated**.

The seventh [agent-to-agent repair](../../docs/agent-to-agent-repair.md) preserves 26 actual
IDs across all three parts: ten inventory entries and sixteen deferred/duplicate concepts.
It makes no vulnerability verdict and does not implement the Agent2Agent protocol.
All seven families now have separate development repairs; original payloads remain inactive.
Combined reporting/policy tests and separately admitted public treatments still follow.

20 October follow-up: these extracted payloads remain immutable and inactive. A separately
versioned repair of tool execution is now in the development package; see
[the repair contract](../../docs/tool-execution-repair.md). Its controlled verification does
not validate the submitted payloads or activate the other six scanners.

The next separate [network/data repair](../../docs/network-data-repair.md) preserves 18 IDs:
10 bounded static conditions, three inventory-only entries and five deferred entries.
It is executable only as a development worker, not an enabled public-scanning profile.
The original payload below remains unchanged and inactive.

The separate [filesystem repair](../../docs/filesystem-repair.md) covers all supplied code:
12 formal IDs (five conditions, five inventory, two deferred), despite the heading claiming 24.
Two legacy markers remain non-emitting metadata. The worker is development-only; no missing
IDs were invented and no public profile/report was activated.

The student supplied seven Markdown documents and stated: "my original code." The provenance
record is that student declaration, not independent authorship verification. The student also
confirmed the intended outcome: integration into the main project and real testing on public
AI-related GitHub repositories. No specific new repository or final evaluation protocol was
selected by this import. No license was assigned.

The fourth separate [memory/state repair](../../docs/memory-state-repair.md) reviewed both parts
and retains all 18 formal IDs: four static conditions, eleven inventory and three deferred.
It removes unvalidated scores and invented MCP state semantics. The original payload stays
unchanged/inactive; the executable repair remains development-only.

The fifth separate [self-modification repair](../../docs/self-modification-repair.md) preserves
27 actual formal IDs despite the 22-rule heading: three syntax conditions, ten inventory entries
and fourteen deferred/duplicate entries. Both parts were inspected. Duplicate concepts do not
emit duplicate alerts; overlap with tool-execution and memory conditions is explicit.
No original payload, public profile or reporting contract is changed.

The sixth [orchestration repair](../../docs/orchestration-repair.md) preserves all 22 supplied
IDs as nine inventory checks and thirteen deferred/duplicate entries. It has no active
security-condition rules: ordinary routing/state/nested calls cannot prove hijacking or leakage.
The bounded inventory worker is executable only for development verification, not activated
in ordinary profiles/reports. The original payload remains unchanged and inactive.

## What Was Transferred

The original Markdown documents remain unchanged in `D:\Project Sonic\new_rules`, outside
the active Git repository (`D:\Project Sonic\Project_Development`). A parent `.gitignore`
excludes `/new_rules/` if the parent becomes a repository later; the development `.gitignore`
also excludes directories named `new_rules` if originals are copied inside it. Neither
instruction can prevent an explicit force-add. No original Markdown document was copied here.

Only the specified Python/YAML line spans were extracted. Multipart snippets were joined in
document order without changing characters, indentation, newlines, logic or scoring. The
`.py.txt` and `.yaml.txt` extensions keep the unvalidated sources out of Python package/import
and test discovery. These are code payloads, not active scanner modules. Unsupported or
malformed code remains preserved for repair; it is not silently removed.

| Source document | Extracted payload |
|---|---|
| `tool_execution_draft.md` | [Python](payloads/tool_execution.py.txt), [YAML](payloads/tool_execution_rules.yaml.txt) |
| `network_data_transfer_draft.md` | [Python](payloads/network_data_transfer_expanded.py.txt) |
| `filesystem_access_draft.md` | [Python](payloads/filesystem_access_final.py.txt) |
| `memory_state_security_draft.md` | [Python](payloads/memory_state_security_expanded.py.txt) |
| `agent_self_modification_draft.md` | [Python](payloads/agent_self_modification_expanded.py.txt) |
| `Agent_Orchestration_draft.md` | [Python](payloads/agent_orchestration_expanded.py.txt) |
| `Agent_to_Agent_draft.md` | [Python](payloads/agent_to_agent_expanded.py.txt) |

[extraction-plan.json](extraction-plan.json) freezes source hashes and one-based, inclusive
line ranges. [payloads/manifest.json](payloads/manifest.json) records source/output hashes,
individual span hashes, the importer hash and a lexical inventory. Counts describe source text,
not executable/reachable rules. The original documents are needed only to replay extraction;
they are not a future runtime dependency.

From the development repository:

```powershell
.venv/Scripts/python.exe -X utf8 tools/import_rule_drafts.py `
  --plan rule_candidates/submitted_2026_10_20/extraction-plan.json `
  --source ../new_rules `
  --output rule_candidates/submitted_2026_10_20/payloads --verify
```

For another extraction, choose a new output directory whose parent already exists.
Existing destinations are never overwritten. The helper reads bounded UTF-8 files as data;
it never imports submitted code, runs its CLI, installs packages or evaluates its expressions.

## Next Integration Work

1. Repair Markdown transport and Python runtime defects in working copies, retaining a diff.
2. Reconcile rule declarations, emission paths, category assignments and dependency requirements.
3. Specify the actual observable condition of each rule and author positive/corrected/near-miss
   controls. Check that normal agent features are not automatically treated as vulnerabilities.
4. Replace standalone unrestricted traversal/plugin loading with our admitted snapshots,
   isolated worker and explicit file/error/coverage accounting.
5. Add a separately versioned producer adapter and profile to existing reporting, preserving
   original evidence and keeping native scores unvalidated rather than turning them into verdicts.
6. Run controlled comparisons first, then separately admit suitable pinned public repositories
   for paired baseline/extended testing. Retain zero findings, errors and unsupported conditions.

See [IMPORT_REVIEW.md](IMPORT_REVIEW.md) for concrete initial blockers and what was actually tested.
There was no scanner execution, product CLI activation, commit or push in this import.
