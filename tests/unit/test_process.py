from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil
import pytest

from agentsec_evidence.execution import process as process_module
from agentsec_evidence.execution.process import run_bounded_process


def _environment() -> dict[str, str]:
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
    return {name: value for name, value in os.environ.items() if name.upper() in allowed}


def test_process_captures_streams_without_shell(tmp_path: Path) -> None:
    marker = "; echo not-a-command"
    capture = run_bounded_process(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); print('err', file=sys.stderr)",
            marker,
        ],
        cwd=tmp_path,
        environment=_environment(),
        timeout_seconds=5,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert capture.exit_code == 0
    assert capture.stdout.decode().strip() == marker
    assert capture.stderr == b"err\r\n" if os.name == "nt" else b"err\n"
    assert capture.timed_out is False


def test_process_timeout_is_explicit(tmp_path: Path) -> None:
    capture = run_bounded_process(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        environment=_environment(),
        timeout_seconds=0.1,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    assert capture.timed_out is True
    assert capture.exit_code != 0


def test_process_output_limit_terminates_process(tmp_path: Path) -> None:
    capture = run_bounded_process(
        [sys.executable, "-c", "print('x' * 10000)"],
        cwd=tmp_path,
        environment=_environment(),
        timeout_seconds=5,
        max_stdout_bytes=100,
        max_stderr_bytes=100,
    )

    assert capture.output_limited is True
    assert capture.stdout_truncated is True
    assert len(capture.stdout) == 100


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_process_interruption_reaps_host_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    observed: list[int] = []

    def interrupt(pid: int) -> int:
        observed.append(pid)
        raise error("authored cancellation")

    monkeypatch.setattr(process_module, "_rss_bytes", interrupt)
    with pytest.raises(error):
        run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            environment=_environment(),
            timeout_seconds=40,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert len(observed) == 1
    assert not psutil.pid_exists(observed[0])
