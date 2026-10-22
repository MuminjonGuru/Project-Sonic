# Corpus Core Execution v1

This additive developer entry point binds the twenty pinned candidate preparations to
the existing static workers. It does not widen historical pilot or authored-case contracts.
The first implementation supports the fixed Python comparison core only. Optional
dependency, MCP JSON and IaC execution require separate admitted bindings; neither their
absence here nor earlier pilot results count as a fresh optional-stage observation.

## Preparation and Admission

`python -m agentsec_evidence.corpus.execution prepare --project . --validation <receipt>
--rules <pinned-rule-directory> --output <new-workspace-preparation>` replays the complete
Git-backed validation receipt, copies exact selected bytes, freezes the current trusted
implementation, unchanged catalogs, rule files/license, tool config, collection protocol,
this specification and license evidence. Preparation does not execute detectors or grant
collection permission. Three fresh repetitions and the prior review protocol remain fixed.

`verify-preparation` replays the preparation and external parent without launching anything.
The JSON preview retains every eligible, unsupported, policy-refused, input-refused and
no-input cell. The forecast is not a count of completed scans. Source-file paths, including
CI/tests/examples, remain accounted for. Oversized or malformed files are never dropped to
make a baseline eligible. Custom partitions do not authorize baseline sharding.

Execution additionally requires `corpus-core-admission-v1`, bound to the exact plan hash
and all located license-evidence hashes. Its named reviewer records provenance and notes
for private-analysis license review, optional-stage applicability/deferment, resource
limits and the exact treatment. This is a traceable decision, not legal certification,
academic approval, independent outcome review or source-redistribution permission. The
runner does not create an approved admission automatically. CI acceptance is an operational
gate before wider collection, not inferred from these JSON documents.

## Invocation and Limits

```powershell
python -m agentsec_evidence.corpus.execution run --project . --preparation <prepared> --admission <review.json> --output <new-workspace-attempt>
python -m agentsec_evidence.corpus.execution verify --project . --output <attempt>
python -m agentsec_evidence.corpus.reporting write --project . --source <attempt> --output <new-output-folder>
python -m agentsec_evidence.corpus.reporting verify --project . --source <attempt> --output <report-folder>
```

All subprocesses use argument arrays, pinned local images, network denial, non-root users,
read-only input/implementation/rules, capability removal and confirmed named-container
cleanup. Never install/import/execute repository code, target tests, agents or models.
No automatic pull, database refresh, retry or resume. A new implementation requires a new
preparation and distinct attempt. The currently approved schema supports only three repeats.

| Producer | Selection | Time | CPU / memory | Output bounds |
|---|---|---|---|---|
| Seven custom families | Exact file-local batches, at most 64 files / 1 MiB | 90 s | 1 / 512 MiB | stdout 2 MiB, stderr 1 MiB |
| Agent Audit Python | Whole eligible Python selection | 120 s | 2 / 2048 MiB | stdout 2 MiB, stderr 1 MiB |
| Semgrep research / policy | Whole selection plus supported policy files | 120 s each | 2 / 2048 MiB | stdout/stderr 4 MiB each; generated native pair 8 MiB |

Custom limits retain 64 PIDs/64 MiB tmpfs. Baselines retain 256 PIDs/256 MiB tmpfs.
Container memory and swap limits are equal. Invocation order is repetition, family/batch,
then Semgrep research/policy and Agent Audit. Stage timings and complete attempt elapsed
time are retained separately; this is not a controlled scanner-speed ranking. The retained
per-repository evidence budget remains 4096 files / 128 MiB, with pre-launch headroom.

## Failure and Interpretation

Every planned row exists before launching. Failures stop that attempt, retain evidence and
leave subsequent rows unrun. Unsupported/refused/failed/unrun counts are null, never zero.
A failed receipt may be replayed for integrity and previously completed rows, but is explicitly
incomplete; it cannot support a full paired comparison. No automatic continuation across
failed rows. Raw stdout/stderr, commands, process metadata and cleanup are retained before
normalization. Cleanup failure is not success.

Native observations are reconciled with exact request/source identity. Semgrep JSON/SARIF
and policy views are checked together; Agent Audit per-file completion stays unobservable.
Custom finding, inventory and limitation counts remain separate. Tool-execution 1.1.0 is
retained; the other six families and upstream rule profiles are unchanged. Orchestration
and agent-to-agent remain inventory-first, not active vulnerability-detection families.

Agent Audit normalization in this derivative replaces the shared adapter's freshly allocated
opaque record ID with a deterministic `finding_corpus_` identity, bound to execution ID,
native SHA-256 and native array position. This is not a native scanner ID. Original native
bytes, evidence pointers and semantic fingerprints are retained; the shared adapter and all
historical finding contracts remain unchanged. Nonempty native findings are regression-tested.

## Offline Report

The portable package contains `report.html`, `report.json` and its checksum manifest only.
It is internal/unredacted, with no copied native/source files, automatic local links, scripts,
external resources or arbitrary evidence exports. Native text is HTML-escaped. Generation
and verification replay the original evidence and require the retained parent paths; this
is not an independently portable native-reproduction bundle.

Per-producer/per-repetition tables preserve all planned states, denominator/omission counts,
condition versus inventory records and semantic repeatability. Failed repetitions are not
summed as zero or excluded silently. Known native timestamps are excluded from Agent Audit
semantic comparison; native bytes are preserved. HTML/JSON counts are not reviewed claims,
unique vulnerabilities, recall, precision or a security score. Core SARIF aggregation and
cross-repository review tables remain separately bounded work; old exports are untouched.

Tests use authored source and simulated process captures. Passing these tests is execution
contract evidence, not a public scan, scanner accuracy measurement or independent review.
