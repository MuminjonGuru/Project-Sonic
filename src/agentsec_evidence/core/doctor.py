from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict


class DoctorCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: Literal["pass", "fail", "unknown"]
    detail: str
    required: bool = True


class DoctorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: list[DoctorCheck]

    @property
    def ready(self) -> bool:
        return all(check.status == "pass" for check in self.checks if check.required)


def _docker_check() -> DoctorCheck:
    docker = shutil.which("docker")
    if docker is None:
        return DoctorCheck(name="docker", status="fail", detail="docker CLI not found")

    try:
        completed = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DoctorCheck(name="docker", status="fail", detail=type(exc).__name__)

    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        return DoctorCheck(name="docker", status="fail", detail=detail or "daemon unavailable")

    version = completed.stdout.decode("utf-8", errors="replace").strip()
    return DoctorCheck(name="docker", status="pass", detail=f"server {version}")


def collect_doctor_report() -> DoctorReport:
    version = sys.version_info
    python_ok = version[:3] == (3, 13, 15)
    python_detail = ".".join(str(part) for part in version[:3])

    return DoctorReport(
        checks=[
            DoctorCheck(
                name="python",
                status="pass" if python_ok else "fail",
                detail=python_detail,
            ),
            _docker_check(),
        ]
    )
