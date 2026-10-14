from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO

import psutil

from agentsec_evidence.core.time import utc_now

_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200


@dataclass(frozen=True)
class ProcessCapture:
    argv: tuple[str, ...]
    started_at: datetime
    ended_at: datetime
    duration_ns: int
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limited: bool
    stdout_truncated: bool
    stderr_truncated: bool
    peak_rss_bytes: int


@dataclass
class _StreamCapture:
    limit: int
    chunks: list[bytes]
    byte_length: int = 0
    truncated: bool = False

    def append(self, chunk: bytes) -> None:
        remaining = self.limit - self.byte_length
        if remaining <= 0:
            self.truncated = True
            return
        accepted = chunk[:remaining]
        self.chunks.append(accepted)
        self.byte_length += len(accepted)
        if len(accepted) != len(chunk):
            self.truncated = True

    def value(self) -> bytes:
        return b"".join(self.chunks)


def _reader(stream: IO[bytes], capture: _StreamCapture, overflow: threading.Event) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            capture.append(chunk)
            if capture.truncated:
                overflow.set()
                return
    finally:
        stream.close()


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        root = psutil.Process(process.pid)
        children = root.children(recursive=True)
    except psutil.Error:
        with suppress(OSError):
            process.kill()
        return
    for child in children:
        with suppress(psutil.Error):
            child.terminate()
    with suppress(OSError):
        process.terminate()

    _gone, alive = psutil.wait_procs(children, timeout=2)
    for item in alive:
        with suppress(psutil.Error):
            item.kill()
    if process.poll() is None:
        process.kill()


def _rss_bytes(process_id: int) -> int:
    try:
        root = psutil.Process(process_id)
        processes = [root, *root.children(recursive=True)]
        return sum(item.memory_info().rss for item in processes if item.is_running())
    except psutil.Error:
        return 0


def run_bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    monitored_files: Sequence[Path] = (),
    max_generated_bytes: int | None = None,
) -> ProcessCapture:
    if not argv or any(not argument or "\x00" in argument for argument in argv):
        msg = "argv must contain non-empty, NUL-free arguments"
        raise ValueError(msg)
    if timeout_seconds <= 0 or max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        msg = "timeout and output limits must be positive"
        raise ValueError(msg)
    if monitored_files and (max_generated_bytes is None or max_generated_bytes <= 0):
        raise ValueError("Monitored output files require a positive aggregate byte limit")

    def generated_limit_exceeded() -> bool:
        if max_generated_bytes is None:
            return False
        try:
            return (
                sum(path.stat().st_size for path in monitored_files if path.exists())
                > max_generated_bytes
            )
        except OSError:
            return True

    creation_flags = _WINDOWS_CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creation_flags,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    # Drain both pipes concurrently so a full stdout or stderr pipe cannot stall the producer.
    # Track truncation/timeouts separately from exit status; generated-file limits are polled.
    overflow = threading.Event()
    stdout_capture = _StreamCapture(max_stdout_bytes, [])
    stderr_capture = _StreamCapture(max_stderr_bytes, [])
    stdout_thread = threading.Thread(
        target=_reader,
        args=(process.stdout, stdout_capture, overflow),
        name="stdout-reader",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_reader,
        args=(process.stderr, stderr_capture, overflow),
        name="stderr-reader",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    output_limited = False
    peak_rss = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        while process.poll() is None:
            peak_rss = max(peak_rss, _rss_bytes(process.pid))
            if overflow.is_set() or generated_limit_exceeded():
                output_limited = True
                _kill_process_tree(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _kill_process_tree(process)
                break
            time.sleep(0.01)

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_tree(process)
            process.wait(timeout=5)
    except BaseException:
        # Cancellation must not orphan the host process; container cleanup is a separate layer.
        with suppress(OSError, psutil.Error):
            _kill_process_tree(process)
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=5)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        raise

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        msg = "Output reader did not terminate"
        raise RuntimeError(msg)
    output_limited = output_limited or overflow.is_set() or generated_limit_exceeded()

    ended_at = utc_now()
    return ProcessCapture(
        argv=tuple(argv),
        started_at=started_at,
        ended_at=ended_at,
        duration_ns=time.monotonic_ns() - started_ns,
        exit_code=process.returncode,
        stdout=stdout_capture.value(),
        stderr=stderr_capture.value(),
        timed_out=timed_out,
        output_limited=output_limited,
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
        peak_rss_bytes=peak_rss,
    )
