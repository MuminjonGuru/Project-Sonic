from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, JsonValue


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def json_bytes(value: JsonValue) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def model_bytes(model: BaseModel) -> bytes:
    value = model.model_dump(mode="json")
    return json_bytes(value)


def jsonl_bytes(models: Iterable[BaseModel]) -> bytes:
    lines = [
        json.dumps(model.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
        for model in models
    ]
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def atomic_write_model(path: Path, model: BaseModel) -> None:
    atomic_write_bytes(path, model_bytes(model))


def atomic_write_jsonl(path: Path, models: Iterable[BaseModel]) -> None:
    atomic_write_bytes(path, jsonl_bytes(models))


def append_model_jsonl(path: Path, model: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(model.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n"
    with path.open("ab") as handle:
        handle.write(line.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
