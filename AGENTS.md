# Development Repository Instructions

## Boundary

This repository contains implementation and execution artifacts. Planning decisions, mentor
notes, and academic provenance remain in `../Project_Phase_02/` and must not be rewritten from
here. Development commits and release hashes may be referenced there.

## Current Development Contract

- CLI/distribution: `agentsec-evidence`
- Python package: `agentsec_evidence`
- Python: 3.13.15 through a committed uv lock
- Host CLI: native Windows or Linux
- Scanner: pinned disposable Docker container
- G1: Semgrep native JSON -> normalized JSONL -> SARIF -> summary
- G2-A: KICS native JSON -> normalized JSONL -> project SARIF -> summary
- KICS native SARIF: retained and checked only as a comparison artifact
- Inputs: project-authored development fixtures only until the corpus pilot gate

G2-A does not authorize Syft/OSV, vendor tools, dynamic testing, a UI, public repositories, or
custom AI-agent checks. Those enter only through their separate eligibility and planning gates.
Do not reinterpret G2-A as completion of the full G2 adapter layer.

## Safety

- Build subprocess commands as argument arrays. Never invoke scanner commands through a shell.
- Mount targets read-only; deny scanner networking; never expose the Docker socket or host home.
- Preserve stdout, stderr, and native reports as bytes before parsing.
- Preserve the exact profile, tool configuration, and rule/query selection used by each run.
- Treat malformed, missing, partial, and timed-out output as explicit failures, never as clean.
- Treat unsupported/not-applicable evidence separately from a successful no-finding scan.
- Never commit credentials, raw third-party targets, private evidence, runtime workspaces, or
  generated outputs.
- Keep development, pilot, held-out, and demo cases separate.

## Required Checks

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
```
