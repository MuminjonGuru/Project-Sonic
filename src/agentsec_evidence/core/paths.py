from __future__ import annotations

import re
import unicodedata
from pathlib import PurePosixPath

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def normalize_relative_path(raw_path: str) -> str:
    if not raw_path or "\x00" in raw_path:
        msg = "Path must be non-empty and contain no NUL byte"
        raise ValueError(msg)

    candidate = unicodedata.normalize("NFC", raw_path.replace("\\", "/"))
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in candidate):
        msg = "Path control and formatting characters are not allowed"
        raise ValueError(msg)
    if candidate.startswith("/") or _WINDOWS_DRIVE.match(candidate):
        msg = "Absolute paths are not allowed"
        raise ValueError(msg)

    path = PurePosixPath(candidate)
    if any(part in {"", ".", ".."} for part in path.parts):
        msg = "Path traversal and dot segments are not allowed"
        raise ValueError(msg)

    normalized = path.as_posix()
    if normalized.startswith("../") or normalized == "..":
        msg = "Path escapes the target root"
        raise ValueError(msg)
    return normalized
