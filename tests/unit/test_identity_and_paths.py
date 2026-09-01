from __future__ import annotations

import pytest

from agentsec_evidence.core.identity import new_opaque_id, semantic_hash
from agentsec_evidence.core.paths import normalize_relative_path


def test_semantic_hash_is_independent_of_mapping_order() -> None:
    first = semantic_hash({"b": 2, "a": 1})
    second = semantic_hash({"a": 1, "b": 2})

    assert first == second


def test_opaque_id_has_requested_prefix() -> None:
    assert new_opaque_id("run").startswith("run_")


@pytest.mark.parametrize("path", ["../escape", "/absolute", "C:\\absolute", "a/../b", ""])
def test_path_policy_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValueError):
        normalize_relative_path(path)


def test_path_policy_normalizes_windows_separator() -> None:
    assert normalize_relative_path("src\\example.py") == "src/example.py"


def test_path_rejects_terminal_and_bidirectional_controls() -> None:
    with pytest.raises(ValueError, match="control and formatting"):
        normalize_relative_path("escape_\x1b[31m.py")
    with pytest.raises(ValueError, match="control and formatting"):
        normalize_relative_path("report_\u202egnp.exe")
