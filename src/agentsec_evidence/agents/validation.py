from __future__ import annotations

import json
import math
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.paths import normalize_relative_path


class AgentDataError(ValueError):
    """Bounded input or native output is invalid; messages do not include source content."""


class AgentResourceLimit(AgentDataError):
    """The configured parser budget was exceeded, not necessarily invalid syntax."""


def canonical_artifact_path(value: str) -> str:
    normalized = normalize_relative_path(value)
    if normalized != value or normalized == ".":
        raise AgentDataError("A canonical relative file path is required")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10))
    for component in value.split("/"):
        if (
            component.endswith((".", " "))
            or any(character in '<>:"|?*' for character in component)
            or component.split(".", 1)[0].upper() in reserved
        ):
            raise AgentDataError("Non-portable artifact path rejected")
    return normalized


def _unique_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise AgentDataError("Duplicate JSON key rejected")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise AgentDataError("Non-finite JSON number rejected")


def load_agent_json(data: bytes, *, max_bytes: int) -> dict[str, JsonValue]:
    """Strict JSON decoding with byte, depth and node budgets; no executable extensions."""
    if max_bytes <= 0 or len(data) > max_bytes:
        raise AgentResourceLimit("JSON byte limit exceeded")
    try:
        document = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
        pending: list[tuple[JsonValue, int]] = [(document, 0)]
        nodes = 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if nodes > 100_000 or depth > 64:
                raise AgentResourceLimit("JSON structure limit exceeded")
            if isinstance(value, dict):
                for key, child in value.items():
                    key.encode("utf-8", errors="strict")
                    pending.append((child, depth + 1))
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
            elif isinstance(value, str):
                value.encode("utf-8", errors="strict")
            elif isinstance(value, float) and not math.isfinite(value):
                raise AgentDataError("Non-finite JSON number rejected")
    except AgentDataError:
        raise
    except (RecursionError, MemoryError) as exc:
        raise AgentResourceLimit("JSON parser resource limit reached") from exc
    except (UnicodeError, ValueError) as exc:
        raise AgentDataError("JSON decoding failed") from exc
    if not isinstance(document, dict):
        raise AgentDataError("Expected a JSON object")
    return cast(dict[str, JsonValue], document)
