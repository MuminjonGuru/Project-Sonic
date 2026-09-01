# Development Repository Instructions

## Boundary

This repository contains implementation and execution artifacts. Planning decisions, mentor
notes, and academic provenance remain in `../Project_Phase_02/` and must not be rewritten from
here. Development commits and release hashes may be referenced there.

## First-Slice Contract

- CLI/distribution: `agentsec-evidence`
- Python package: `agentsec_evidence`
- Python: 3.13.15 through a committed uv lock
- Host CLI: native Windows or Linux
- Scanner: pinned disposable Docker container
- Initial pipeline: Semgrep native JSON -> normalized JSONL -> SARIF -> summary
- Inputs: project-authored development fixtures only until the pilot gate

Do not add KICS, dependency scanners, vendor tools, dynamic testing, a UI, public repositories,
or custom AI-agent checks to the first slice.

## Safety

- Build subprocess commands as argument arrays. Never invoke scanner commands through a shell.
- Mount targets read-only; deny scanner networking; never expose the Docker socket or host home.
- Preserve stdout, stderr, and native reports as bytes before parsing.
- Treat malformed, missing, partial, and timed-out output as explicit failures, never as clean.
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
