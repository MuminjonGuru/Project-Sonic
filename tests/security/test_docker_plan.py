from __future__ import annotations

from pathlib import Path

from agentsec_evidence.execution.config import (
    ExecutionProfile,
    KicsToolConfig,
    SemgrepToolConfig,
    load_toml_config,
)
from agentsec_evidence.execution.docker import (
    build_kics_argv,
    build_semgrep_argv,
    portable_docker_argv,
)


def test_semgrep_plan_enforces_static_sandbox(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    tool = load_toml_config(root / "configs" / "tools" / "semgrep.toml", SemgrepToolConfig).value
    profile = load_toml_config(
        root / "configs" / "profiles" / "development.toml", ExecutionProfile
    ).value
    docker = tmp_path / "docker.exe"
    docker.touch()
    target = tmp_path / "target"
    target.mkdir()
    rule = tmp_path / "rule.yml"
    rule.touch()
    output = tmp_path / "output"
    output.mkdir()

    argv = build_semgrep_argv(
        docker_executable=docker,
        tool=tool,
        profile=profile,
        container_name="agentsec-evidence-test",
        target_root=target,
        rule_file=rule,
        output_root=output,
    )

    joined = " ".join(argv)
    assert argv[1:3] == ["run", "--rm"]
    assert "--network none" in joined
    assert "--read-only" in argv
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "target=/src,readonly" in joined
    assert "target=/rules.yml,readonly" in joined
    assert "target=/output,readonly" not in joined
    assert "docker.sock" not in joined.lower()
    assert "--pull never" in joined

    portable = portable_docker_argv(
        argv,
        docker_executable=docker,
        mount_replacements={target: "TARGET", rule: "RULE", output: "OUTPUT"},
    )
    serialized = " ".join(portable)
    assert portable[0] == "docker"
    assert str(tmp_path) not in serialized
    assert "source=<TARGET>" in serialized


def test_kics_plan_enforces_static_sandbox_and_frozen_queries(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    tool = load_toml_config(root / "configs" / "tools" / "kics.toml", KicsToolConfig).value
    profile = load_toml_config(
        root / "configs" / "profiles" / "development.toml", ExecutionProfile
    ).value
    docker = tmp_path / "docker.exe"
    docker.touch()
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "output"
    output.mkdir()

    argv = build_kics_argv(
        docker_executable=docker,
        tool=tool,
        profile=profile,
        container_name="agentsec-kics-test",
        target_root=target,
        output_root=output,
    )

    joined = " ".join(argv)
    assert argv[1:3] == ["run", "--rm"]
    assert "--network none" in joined
    assert "--read-only" in argv
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "--user 65534:65534" in joined
    assert "target=/src,readonly" in joined
    assert "target=/output,readonly" not in joined
    assert "docker.sock" not in joined.lower()
    assert "--pull never" in joined
    assert "--disable-secrets" in argv
    assert "--disable-full-descriptions" in argv
    assert "--exclude-gitignore" in argv
    assert argv.count("--include-queries") == 1
    assert ",".join(tool.include_queries) in argv
    assert ",".join(tool.platforms) in argv
    assert tool.image in argv

    portable = portable_docker_argv(
        argv,
        docker_executable=docker,
        mount_replacements={target: "TARGET", output: "OUTPUT"},
    )
    serialized = " ".join(portable)
    assert portable[0] == "docker"
    assert str(tmp_path) not in serialized
    assert "source=<TARGET>" in serialized
    assert "source=<OUTPUT>" in serialized
