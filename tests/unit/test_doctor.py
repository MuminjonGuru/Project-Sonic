from __future__ import annotations

from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.doctor import DoctorCheck, DoctorReport

runner = CliRunner()


def test_report_ready_requires_all_required_checks() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(name="python", status="pass", detail="3.13.15"),
            DoctorCheck(name="optional", status="fail", detail="missing", required=False),
        ]
    )

    assert report.ready is True


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"
