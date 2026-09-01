# Third-Party Dependency Notice

This file is a development record, not a final legal determination. Exact dependencies and
license metadata are generated from the committed `uv.lock` before any public release.

The first-slice runtime uses Pydantic, Typer, Rich, jsonschema, psutil, and portalocker. Semgrep
is an external scanner executed in its own pinned container; its engine and rule licensing are
recorded separately. No Semgrep-maintained rule pack is redistributed by this repository.

Development-only type metadata includes `types-psutil`, an Apache-2.0 typeshed package matched
to psutil 7.2.2, and `types-jsonschema`, an Apache-2.0 typeshed package matched to jsonschema
4.26.0.

The unmodified OASIS SARIF 2.1.0 JSON Schema is vendored only for offline conformance
validation. It was retrieved from the OASIS normative publication URL on 2026-08-31; its
source, SHA-256, and status are recorded in `schemas/vendor/oasis/README.md`. OASIS notices and
terms continue to apply. This repository does not claim ownership of that schema.

The control image uses the exact `python:3.13.15-slim` base digest recorded in its Dockerfile.
It packages the CLI and offline resources but receives no Docker socket; scanner execution is a
separate pinned container launched by an authorized host CLI.
