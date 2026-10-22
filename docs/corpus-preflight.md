# Corpus Selection And Offline Preflight

This additive increment prepares the recorded twenty-candidate shortlist for a descriptive
engineering study. It does not authorize security scanning or change the two-pilot execution
contracts, worker limits, rules, images or vulnerability database.

`test_cases/corpus/candidates-2026-10-21.json` is an executable-input **candidate manifest**,
not an execution plan. It records the exact revisions and selection metadata from the private
working plan without copying that plan into Git. Twenty includes the two existing formative
pilots. The other eighteen are prospective descriptive candidates, not confirmatory/held-out
cases. Shared framework lineage and project roles need contextual interpretation.

## Preparation And Evidence

`tools/acquire_corpus_candidate.py` performs explicitly requested online acquisition through
`gh api`: public repository metadata, the pinned commit/tree and source archive. It retains
commands, exit/timeout/output-limit status and exact responses. Failed attempts are retained;
destinations cannot be reused. Tokens are neither requested nor copied into commands/evidence.

The existing exact-identity helper recovers supported signed commit layouts. When that layout
is unavailable, a fresh bare Git object store fetches only the pinned shallow revision with
blob filtering. It has no checkout, hooks, target imports or package installation; inherited
Git configuration is disabled. A hash check still binds the raw commit to the selected SHA.
This verifies object consistency, not author signatures or repository origin independently.

Cached source passes the existing complete-tree intake: commit/tree/blob reconstruction,
archive membership, content hashes, both materialized copies and an offline receipt replay.
Links, submodules, LFS pointers and size/path violations remain unsupported. Failed metadata,
acquisition or preparation does not become a zero-finding result. Raw caches and targets stay
under ignored `workspace/`; no third-party source is added to Git.

License filenames and exact hashes are retained for review. GitHub's SPDX field is metadata;
preflight leaves the intake license status unknown and source-specific review pending. Neither
file presence nor a familiar license header grants blanket redistribution clearance.

## Preview Meaning

`intake/corpus.py` replays the prepared source against its external specification and candidate.
It selects all exact `.py` paths, including tests, CI, examples and documentation. Path-role
labels are explicit filename heuristics. The full artifact inventory remains separately bound.

| Stage | Preview behavior |
|---|---|
| Seven custom families | Deterministic file-local partitions using unchanged 64-file/1-MiB limits; individually oversized files remain selected but explicitly unsupported |
| Semgrep paired views | Whole Python selection plus required policy files; unchanged limits and full-parent policy inspection; no baseline sharding |
| Agent Audit Python | Whole Python selection and parent configuration-filename guards; isolated syntax and inline-marker checks still pending |
| Optional stages | Candidate filenames for lockfiles, MCP JSON, Terraform and YAML only; format/applicability not inferred, Dockerfile remains unsupported |

`pending-validation` means only that this size/policy preflight has no recorded blocking
condition. It is not ready-to-run, complete analysis or a safe result. `unsupported-size`,
`policy-refused` and `no-input` remain distinct. Every stage has zero scanner invocations and
null findings. Python AST/JSON artifact parsing, output budgets, licensing review, exact stage
admission and the frozen collection/review protocol remain subsequent gates.

Preview replay checks every derived field against the verified source, external candidate and
specification. Editing hashes alongside a preview cannot bypass that source reconstruction.
The portable JSON schema validates structure, not the source evidence by itself.

## Commands

Run online preparation once per declared candidate into a fresh destination with an existing
parent directory. There is no automatic bulk scan or retry:

```powershell
.venv/Scripts/python.exe -X utf8 tools/acquire_corpus_candidate.py `
  --candidates test_cases/corpus/candidates-2026-10-21.json --id R03 `
  --output workspace/corpus-admission-2026-10-22/R03
```

Offline replay, without network or Docker:

```powershell
.venv/Scripts/python.exe -X utf8 tools/preview_corpus_candidate.py verify `
  --candidates test_cases/corpus/candidates-2026-10-21.json --id R03 `
  --spec workspace/corpus-admission-2026-10-22/R03/intake-spec.json `
  --prepared workspace/corpus-admission-2026-10-22/R03/prepared `
  --output workspace/corpus-admission-2026-10-22/R03/preflight
```

Do not silently remove large files or replace projects after seeing findings. Before collection,
resolve whether over-limit projects stay as explicitly unmatched observations or receive a
separately validated larger **whole-selection** baseline treatment. No such choice is made by
this preview. Keep final selection decisions independent of scanner findings.

## Recorded Outcome And Student Decision

The 22 October preparation verified all twenty complete pinned sources and retained all
acquisition commands, bytes and replayed previews. No security scanner or target code ran.
Thirteen are within the existing baseline size envelope. The seven outside are R07 (dbt-mcp),
R12 (ai-hedge-fund), R13 (OpenManus), R16 (smolagents), R17 (aisuite), R19 (llama-agents) and
R20 (TaskWeaver). All selected Python files are individually within the custom input limit;
the full corpus partitions into 42 custom batches without omitted Python files.

After seeing this preflight, the student approved **retaining all twenty, comparing the
eligible subset and recording unsupported baseline stages explicitly**. No size increase or
baseline sharding is approved. The thirteen are provisional: isolated syntax/policy validation
can still narrow the paired comparison. Report unmatched custom observations separately,
never as a baseline detection improvement. Two existing pilots remain formative.

Local evidence: `outputs/corpus_preflight_2026-10-22/README.md` and `cohort-preflight.json`.
The complete Linux regression passed 2,734 tests; 116 focused Windows tests passed. Ruff and
mypy passed. A full Windows suite was not rerun. License files were located and hashed;
source-specific licensing review, optional-stage selection, execution admission and the
collection/review protocol freeze remain open.
