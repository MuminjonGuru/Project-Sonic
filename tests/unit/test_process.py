from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

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


def _assert_child_terminated(child: subprocess.Popen[bytes]) -> None:
    # Windows can retain a terminated PID while an exception traceback keeps its handle open.
    # Require the runner to have observed termination, not the kernel to have deleted the PID.
    assert child.returncode is not None, "Child termination was not confirmed"
    assert child.wait(timeout=0) == child.returncode
    assert child.stdout is not None and child.stdout.closed
    assert child.stderr is not None and child.stderr.closed


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_process_interruption_confirms_child_termination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    observed: list[int] = []
    children: list[subprocess.Popen[bytes]] = []
    popen = subprocess.Popen
    interruption = error("authored cancellation")

    def record_child(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child: subprocess.Popen[bytes] = popen(*args, **kwargs)
        children.append(child)
        return child

    def interrupt(pid: int) -> int:
        observed.append(pid)
        raise interruption

    monkeypatch.setattr(subprocess, "Popen", record_child)
    monkeypatch.setattr(process_module, "_rss_bytes", interrupt)
    try:
        with pytest.raises(error, match="authored cancellation") as caught:
            run_bounded_process(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=tmp_path,
                environment=_environment(),
                timeout_seconds=40,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        assert caught.value is interruption
        assert len(children) == 1
        assert observed == [children[0].pid]
        _assert_child_terminated(children[0])
    finally:
        # Test failures must not leave a sleeping child; cleanup happens after the assertions.
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()


def test_termination_check_rejects_live_child(tmp_path: Path) -> None:
    with subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        env=_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    ) as child:
        try:
            assert child.poll() is None
            with pytest.raises(AssertionError, match="Child termination was not confirmed"):
                _assert_child_terminated(child)
        finally:
            child.kill()
            child.wait(timeout=5)
