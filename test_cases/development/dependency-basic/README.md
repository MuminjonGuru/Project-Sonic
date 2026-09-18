# Dependency Development Case

This is a project-authored, deliberately small uv lockfile fragment. It is not a real resolved
installation and must never be installed. It tests evidence handling across both Python marker
branches, two Requests versions, a shared transitive urllib3 record, the development-group
packaging record, and a separately accounted editable root. Input bytes are frozen before
tool runs. The adjacent OSV config intentionally suppresses everything; the explicit shared
baseline config must override it.

`expected.json` is a finite oracle written from authored inputs and downloaded advisory ranges,
not from either scanner's results. The student explicitly approved this finite test scope on
2026-09-18. This is not external academic approval or a complete real-world vulnerability oracle.
The public repository pilot remains gated on the remaining compatibility and admission checks.

The three named Requests advisory groups apply to 2.31.0; their fixed versions are 2.32.0,
2.32.4, and 2.33.0. Negative observations are relative to the hashed database, not universal
security claims. Advisory bytes and the complete database stay in the private workspace.
