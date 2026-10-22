# Repository Custom Rehearsal

22 October 2026. This additive treatment implements the student's requested annotation
correction, repository execution/report binding and two-existing-pilot rehearsal. It does
not admit the prescreened wider corpus or modify historical evidence/contracts.

## Annotation Correction

`custom_rules/tool_execution_v2.py` and `tool_execution_v2_worker.py` provide version 1.1.0,
with `tool-execution-static-v2` native output. The original module, worker, catalogs and
1.0.0 results remain unchanged. The five rule IDs remain the same; condition identities
include the new implementation version. The other six workers are unchanged.

The old visitor descended into `from __future__ import annotations` expressions as though
they were ordinary calls. The new visitor distinguishes postponed and function-local
variable annotations, preserves assignment-value and target-expression checks, and retains
eager module/class annotations under Python 3.13 semantics. Lazy type-alias scopes are
explicitly unsupported. Function-signature annotations and later introspection remain
limitations; this is not a complete annotation or reachability analysis.

Among the 385 existing authored inputs, the condition-ID sequence changes only for
`memory-state/annotation-not-code.py`: its tool-execution eval report is removed. The
annotation is retained as a limitation observation. This development correction is not
an accuracy estimate and does not change upstream Semgrep behavior.

Language basis: [Python 3.13 annotated assignment semantics](https://docs.python.org/3.13/reference/simple_stmts.html#annotated-assignment-statements)
and [postponed annotations](https://docs.python.org/3.13/library/__future__.html).
These establish the declared language treatment, not the actual runtime of each target.

## Scope And Execution

The new `repository-custom-plan-v1` admits only:

| Target | Pinned revision | Selected Python files |
|---|---|---:|
| langchain-samples/cicd-pipeline-example | 5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf | 26 |
| qdrant/mcp-server-qdrant | c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41 | 19 |

1. Replay the completed source pilot, including Git/input evidence, tool outputs and database.
2. Select every `.py` file from that verified Git inventory. Do not accept arbitrary directories.
3. Freeze package source, exact requests, catalogs, parent evidence/report hashes and image ID.
4. Give all seven custom workers the same byte-identical selection, in deterministic bounded
   partitions, one worker at a time. Both present pilots fit a single partition.
5. Retain exact commands, stdout/stderr, exits, duration, cleanup and all native records.
6. Seal new attempts. Offline replay rechecks source/parent/native/command bindings and tables.

Workers retain the existing no-network, read-only, non-root, one-CPU/512-MiB/64-PID,
90-second and bounded-output policy. No target imports, installation, tests, agent execution,
dynamic plugins or host AST parsing of repository files. No automatic retries or overwrites.
An unfinished attempt remains sealed evidence of failure; it cannot become a successful report.

This custom batching policy is not applied to Agent Audit or Semgrep. The original baseline
runners still scan their full admitted views under their original limits. Larger public
repositories require a separate admission/size decision, not silent baseline sharding.

## Report Binding

`reporting/repository.py` produces `repository-evidence-report-v1`, separate from legacy
common-report v1-v5. It replays the custom attempt and its parent baseline. Qdrant is read
through its own native contract, never passed to the original LangGraph-only loader.

The portable derivative contains:

- `report.html`: script-free offline presentation with escaped data and restrictive CSP.
- `report.json`: exact custom native text/projections, baseline report, native/export
  references, full artifact inventory, per-family state/counts and all repeated records.
- `results.sarif`: separate baseline views/stages/repetitions and custom-family runs.
  Only active custom conditions become results; no invented vulnerability for inventory.
- `manifest.json`: exact package membership, hashes and byte lengths.

Only these explicit derivatives are exported. Source trees and raw native bundles are not
automatically copied. JSON remains internal/unredacted and can contain native expressions
or local paths. This is not the previously approved screen-sharing redacted view and is
not automatically release-cleared.

The HTML shows the first custom repetition in its summary and condition list. Every baseline
row and all repetitions remain in the structured evidence. Baseline and custom durations
belong to separate attempts; they are not a combined timing measurement. The report assigns
neither an overall security score nor a unique vulnerability count. It does not merge overlaps,
equate package presence with matching completion, or apply suppressions to custom findings.

Package verification checks hashes, embedded custom/request projections and regenerated
HTML/SARIF. It does **not** rerun scanners or independently attest to original evidence.
Full native replay needs the original attempts and frozen database.

## Commands

Run the original pinned baseline first using `tools/run_source_pilot.py` or
`python -m agentsec_evidence.pilot.qdrant run`; use a fresh attempt for each.

```powershell
.venv/Scripts/python.exe -X utf8 -m agentsec_evidence.custom_rules.repository_execution run `
  --project . --target langgraph-cicd --baseline <completed-baseline-attempt> `
  --database <frozen-PyPI-all.zip> --output <fresh-workspace-attempt> --repetitions 3

.venv/Scripts/python.exe -X utf8 -m agentsec_evidence.reporting.repository build `
  --project . --input <custom-attempt> --database <frozen-PyPI-all.zip> `
  --output <fresh-report-folder>

.venv/Scripts/python.exe -X utf8 -m agentsec_evidence.reporting.repository verify `
  --output <report-folder>
```

Use `qdrant-mcp` for the second target. Keep the private final plan outside Git. Wider
collection follows evidence review and explicit byte-level repository/treatment admission.
