# Python Repository Evaluation Results

Prepared 25 October 2026 from retained 22 October evidence. No scanners were rerun for this package.
This is a curated results summary for review in the existing private repository, not a raw evidence release.

## Read the Results

- [Offline HTML summary](report.html): download this file and open it in a browser. GitHub displays HTML source, not the rendered report.
- [Machine-readable summary and source hashes](summary.json).
- [Repository revisions and first-repetition counts](repositories.csv).
- [Per-repository Semgrep file accounting](coverage.csv).
- [All repository-stage repeatability outcomes](repeatability.csv).
- [File checksums](checksums.json).

## Main Results

| Measurement | Retained result |
|---|---:|
| Pinned repositories | 20 |
| Selected Python file occurrences | 1,903 |
| Baseline-eligible repository selections / files | 13 / 309 |
| Baseline-unsupported selections / files | 7 / 1,594 |
| Repetitions | 3 |
| Retained core scanner invocations | 999 |
| Equal semantic repository-stage comparisons | 179 |
| Comparisons not assessed because the stage was unsupported | 21 |

The prototype produced evidence-linked outputs, retained explicit unsupported states, and
reproduced normalized semantic results across the three retained repetitions. The results
demonstrate bounded pipeline operation and evidence accounting, not comprehensive agent security.

## Method

The collection used seven custom Python families and, where admitted, the unchanged 68-rule
GitLab Python Semgrep profile in research and repository-policy views, plus pinned Agent Audit.
Both Semgrep views disabled `.gitignore` filtering; the policy view applied Semgrep ignore files
and inline suppressions. Native policy distinctions remain in the original evidence.
Targets were pinned, selected Python inputs validated, and tools run sequentially in isolated
containers without executing target code, installing dependencies or operating live agents.

See the [collection protocol](../../corpus-collection-protocol.md),
[execution contract](../../corpus-core-execution.md),
[report-only recovery](../../corpus-report-recovery.md) and
[candidate revisions](../../../test_cases/corpus/candidates-2026-10-21.json).
The candidate manifest records prescreening, not execution permission; separate admissions
governed collection. The original failed dbt report attempt was retained. A linked report-only
recovery reused its completed scans without adding scanner invocations.

## Repository Results

All counts below are **first-repetition records**, not unique vulnerabilities. Custom totals
exclude inventory and limitations. Unsupported baseline results are not zero. Do not add
the research and policy columns: they are different views of overlapping input evidence.

| ID | Pinned repository | Python files | Custom conditions | Semgrep research | Semgrep policy | Agent Audit |
|---|---|---:|---:|---:|---:|---:|
| R01 | [langchain-samples/cicd-pipeline-example](https://github.com/langchain-samples/cicd-pipeline-example/tree/5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf) | 26 | 15 | 0 | 0 | 8 |
| R02 | [qdrant/mcp-server-qdrant](https://github.com/qdrant/mcp-server-qdrant/tree/c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41) | 19 | 0 | 2 | 2 | 2 |
| R03 | [chroma-core/chroma-mcp](https://github.com/chroma-core/chroma-mcp/tree/98ff67589bdcc31b730a5415ff9529433f949077) | 3 | 0 | 0 | 0 | 1 |
| R04 | [redis/mcp-redis](https://github.com/redis/mcp-redis/tree/b814c36c6309d5e2e5ea238b86ff25f60edc0ce8) | 44 | 1 | 0 | 0 | 6 |
| R05 | [motherduckdb/mcp-server-motherduck](https://github.com/motherduckdb/mcp-server-motherduck/tree/41acb581d9bc04e427655ba5178b2c5c01f68cd2) | 31 | 1 | 1 | 0 | 12 |
| R06 | [neo4j-contrib/mcp-neo4j](https://github.com/neo4j-contrib/mcp-neo4j/tree/1c7ad0793b5f06b42b9c44f855c23eb2064c3bb7) | 50 | 14 | 188 | 16 | 130 |
| R07 | [dbt-labs/dbt-mcp](https://github.com/dbt-labs/dbt-mcp/tree/3365e6dd75d1bb4ff92cceb25da6d1a59454b002) | 273 | 9 | unsupported-size | unsupported-size | unsupported-size |
| R08 | [MarkusPfundstein/mcp-obsidian](https://github.com/MarkusPfundstein/mcp-obsidian/tree/5ee0b84fa8319fd2fdf0db0ee1febb065e712a15) | 15 | 13 | 0 | 0 | 13 |
| R09 | [ckreiling/mcp-server-docker](https://github.com/ckreiling/mcp-server-docker/tree/57a7df208fdc2362505835f670e53c66f3717c48) | 5 | 0 | 0 | 0 | 2 |
| R10 | [langchain-ai/local-deep-researcher](https://github.com/langchain-ai/local-deep-researcher/tree/96555649619b9c482442f2cba043312bd7692507) | 7 | 3 | 1 | 1 | 8 |
| R11 | [langchain-ai/open_deep_research](https://github.com/langchain-ai/open_deep_research/tree/1b7d2e80db9faa586165c60e09096dbbfd483a64) | 22 | 18 | 20 | 19 | 17 |
| R12 | [virattt/ai-hedge-fund](https://github.com/virattt/ai-hedge-fund/tree/4e1657ddc689e3939c481a8f0955444b10f02dc9) | 118 | 7 | unsupported-size | unsupported-size | unsupported-size |
| R13 | [FoundationAgents/OpenManus](https://github.com/FoundationAgents/OpenManus/tree/3309bf4e416fb1c74b008f3e86494439a31bad53) | 90 | 14 | unsupported-size | unsupported-size | unsupported-size |
| R14 | [langchain-ai/react-agent](https://github.com/langchain-ai/react-agent/tree/087d90d0c876668956b733a104f1708cef0128e2) | 12 | 1 | 3 | 0 | 1 |
| R15 | [langchain-ai/retrieval-agent-template](https://github.com/langchain-ai/retrieval-agent-template/tree/6a441ef6018b5465c5e97f4b3ca88b807b4b6fb2) | 13 | 0 | 0 | 0 | 1 |
| R16 | [huggingface/smolagents](https://github.com/huggingface/smolagents/tree/96f33faaf028479119ec8d34507b47694cf14e34) | 75 | 71 | unsupported-size | unsupported-size | unsupported-size |
| R17 | [andrewyng/aisuite](https://github.com/andrewyng/aisuite/tree/66c7890c2d68c2d67f41723bc848bb6713d82a9c) | 355 | 68 | unsupported-size | unsupported-size | unsupported-size |
| R18 | [openai/swarm](https://github.com/openai/swarm/tree/6af0b4caf37dca4526dfd98e9fbd8ce36e7eeb22) | 62 | 29 | 4 | 2 | 16 |
| R19 | [run-llama/llama-agents](https://github.com/run-llama/llama-agents/tree/656b3fc5a37debfb44ddcf90b51488e59e3564d4) | 516 | 102 | unsupported-size | unsupported-size | unsupported-size |
| R20 | [microsoft/TaskWeaver](https://github.com/microsoft/TaskWeaver/tree/d44ddef23f90059fb17999d3095db4240e98f955) | 167 | 90 | unsupported-size | unsupported-size | unsupported-size |

## Custom Families

| Family | First-repetition condition records | Treatment |
|---|---:|---|
| tool-execution | 20 | Static conditions |
| network-data | 128 | Static conditions |
| filesystem | 263 | Static conditions |
| memory-state | 41 | Static conditions |
| self-modification | 4 | Static conditions |
| orchestration | 0 | Inventory-first |
| agent-to-agent | 0 | Inventory-first |

Custom conditions total **456 across 20 repositories**. Baseline totals are **219** Semgrep
research, **40** Semgrep policy and **217** Agent Audit records, each on **13 repositories**.
Different denominators and assertion scopes prevent an accuracy or superiority conclusion.

## Coverage and Repeatability

Across the 309 baseline-selected file occurrences, Semgrep research reported 309 paths.
Policy reported 182, marked 43 as native-skipped, and did not report 84. Twelve policy views
were incomplete; one was not-established. Reported paths do not prove exhaustive rule
application. Agent Audit per-file completion remains unknown.

A comparison row means one repository-stage assessed across three repetitions, with any
custom batches aggregated. These 200 rows are not 200 experiments or 999 invocations.

| Stage | Equal | Not assessed |
|---|---:|---:|
| tool-execution | 20 | 0 |
| network-data | 20 | 0 |
| filesystem | 20 | 0 |
| memory-state | 20 | 0 |
| self-modification | 20 | 0 |
| orchestration | 20 | 0 |
| agent-to-agent | 20 | 0 |
| semgrep-research | 13 | 7 |
| semgrep-policy | 13 | 7 |
| agent-audit-python | 13 | 7 |

## Limitations and Review Status

- Counts are first-repetition condition or native finding records, not unique or confirmed vulnerabilities. Cross-rule, cross-tool and policy-view overlaps are not deduplicated.
- Custom conditions cover 20 selected repositories; baselines cover only 13. Do not compare whole-corpus totals as detector superiority or accuracy.
- Seven baseline selections are unsupported by the frozen harness size contract, not proven beyond the upstream scanners' capacity. Their counts remain null, not zero.
- R01 and R02 are previously inspected formative pilots. The other 18 are purposive descriptive cases, not held-out accuracy data or independent random samples.
- Three repetitions measure semantic agreement at fixed inputs, tool/rule pins and configuration. They are not independent vulnerability samples or evidence of cross-machine reproduction.
- File reporting is not exhaustive security coverage. Twelve executed Semgrep policy views are incomplete; the remaining view is not-established. Agent Audit per-file completion remains unknown.
- Orchestration and agent-to-agent families are inventory-first. Their zero condition count does not establish absence of those risks. Inventory and limitation records are excluded from condition totals.
- The 72-record source-context review is AI-drafted with student review pending and no independent reviewer. This summary makes no precision, recall, exploitability, prevalence or compliance claim.
- Dependency, MCP JSON and IaC results are separate treatments, not part of this Python-only collection. Targets, dependencies and live agents were not executed.
- This curated derivative omits native reports, source excerpts, per-finding locations, messages and local paths. Hashes identify retained inputs but do not independently attest to their validity; this package alone cannot replay native evidence.
- This package is approved for the existing private repository. It does not settle institutional ownership, source licensing or public-release permission.
