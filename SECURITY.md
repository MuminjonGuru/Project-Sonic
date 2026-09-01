# Security Policy

## Research Safety Boundary

The project currently analyzes only project-authored fixtures. Do not scan a public or private
third-party repository until its provenance, license, target manifest, and applicable research
profile have passed the documented eligibility gate.

Never provide a scanner container with host credentials, the Docker socket, a writable target,
or unrestricted network access. A safety-control failure stops affected execution until the
failure is investigated and the security acceptance tests pass again.

Target paths containing traversal, absolute paths, control/format characters, symlinks, or
portable Unicode/case collisions are refused during snapshot intake. Finalized run bundles are
read-only by application policy and must pass manifest/hash validation before use. Normalized
and SARIF outputs remain private by default because scanner messages can contain source text or
secrets.

## Reporting

Report suspected vulnerabilities privately to the student researcher. Do not place unresolved
live findings, credentials, exploit details, or vendor-restricted output in issues, commits,
screenshots, demonstrations, or public artifacts.
