# Third-Party Dependency Notice

This file is a development record, not a final legal determination. Exact dependencies and
license metadata are generated from the committed `uv.lock` before any public release.

The runtime uses Pydantic, Typer, Rich, jsonschema, psutil, and portalocker. Semgrep and KICS are
external scanners executed in separate pinned containers; their software and content licensing
are recorded separately. No Semgrep-maintained rule pack or KICS built-in query pack is
redistributed by this repository.

KICS v2.1.20 is used under Apache-2.0 from an image pinned by digest. Its corresponding source
revision, image digest, built-in query-pack inventory hash, selected query IDs, and observed
software/query licenses are recorded in `configs/tools/kics.toml`. The IaC fixtures are
project-authored. Captured KICS outputs can contain tool-emitted query metadata and remain
internal pending release review. The external image must be obtained from its publisher; its
license and notices continue to apply.

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
