# Four Authored URL Contrasts

The student approved this finite development scope on 18 October 2026. Exact fixture text is
AI-authored. Expected source conditions are not derived from analyzer outcomes and have not
received independent review. See [the contract](../../../docs/agent-url-contrast.md).

Inputs are inert strings in `cases.json`, materialized only by the bounded static runner. Do not
import them, install LangChain, send network requests or execute the depicted functions.

The four cases are one related development family: direct tool URL input, fixed non-tool URL,
fixed tool URL and fixed allowlisted tool destinations. The last three remove the named direct
caller-URL condition only; none is a general security guarantee. Redirects and runtime reachability
are deliberately outside the condition.

The registry is byte-pinned in `agents/url_contrast.py`; changing it requires a new explicit
treatment revision. Existing `agent-artifacts` and benchmark case registries remain unchanged.
