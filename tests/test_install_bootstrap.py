from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import install_host


def _without_python_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"}
    }


def test_help_and_preflight_validation_bootstrap_without_site_packages(tmp_path: Path) -> None:
    script = Path(install_host.__file__).resolve()
    root = script.parents[1]
    environment = _without_python_environment()

    help_result = subprocess.run(
        [sys.executable, "-S", str(script), "--help"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    preflight_result = subprocess.run(
        [
            sys.executable,
            "-S",
            str(script),
            "--preflight",
            "--public-ip",
            "not-an-ip",
            "--runtime-dir",
            str(tmp_path / "runtime"),
            "--hermes-user",
            "hermes",
            "--trusted-bundle-root",
            str(root),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert help_result.returncode == 0, help_result.stderr
    assert "PRIVILEGED-HOST-INSTALL" in help_result.stdout
    assert "ModuleNotFoundError" not in help_result.stderr
    assert preflight_result.returncode == 2
    assert json.loads(preflight_result.stderr)["error"]["code"] == "INVALID_PUBLIC_IP"
    assert "ModuleNotFoundError" not in preflight_result.stderr


@pytest.mark.parametrize(("staging", "environment_flag"), [(True, "--staging"), (False, "--production")])
def test_managed_tls_handoff_uses_pinned_interpreter_and_real_setup_cli(
    tmp_path: Path, staging: bool, environment_flag: str
) -> None:
    root = tmp_path / "trusted-bundle"
    setup_script = root / "scripts" / "setup_tls.py"
    observed: list[tuple[str, ...]] = []

    def command_boundary(argv):
        command = tuple(str(part) for part in argv)
        observed.append(command)
        return install_host.CommandResult(0)

    config = install_host.InstallConfig(
        public_ip="203.0.113.17",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        hermes_group="hermes",
        trusted_bundle_root=root,
        profile="work",
        email="operator@example.test",
        production=not staging,
    )

    install_host._run_managed_tls_setup(config, staging=staging, execute=command_boundary)

    assert len(observed) == 1
    command = observed[0]
    assert command[:3] == (str(install_host.DEFAULT_PYTHON), "-I", "-c")
    assert command[4:6] == (str(setup_script), str(root))
    assert command[6:9] == ("--apply", "--confirm", install_host.setup_tls.CONFIRMATION)
    assert environment_flag in command
    assert "--renewal-scheduler-verified" in command
    assert ("--python-executable", str(install_host.DEFAULT_PYTHON)) == tuple(
        command[index : index + 2] for index in range(len(command) - 1) if command[index] == "--python-executable"
    )[0]


def test_preflight_rejects_existing_untrusted_venv_before_any_command(tmp_path: Path, monkeypatch) -> None:
    managed_venv = tmp_path / "installer-venv"
    (managed_venv / "lib" / "python3.11" / "site-packages").mkdir(parents=True)
    (managed_venv / "lib" / "python3.11" / "site-packages" / "attacker.pth").write_text(
        "import attacker\n", encoding="utf-8"
    )
    managed_python = managed_venv / "bin" / "python"
    managed_python.parent.mkdir()
    managed_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(install_host, "INSTALLER_VENV", managed_venv)
    monkeypatch.setattr(install_host, "DEFAULT_PYTHON", managed_python)
    monkeypatch.setattr(
        install_host,
        "_validate_managed_venv",
        lambda **kwargs: (_ for _ in ()).throw(PermissionError("unsafe site-packages")),
    )
    monkeypatch.setattr(
        install_host.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("unsafe managed interpreter reached command boundary"),
    )
    config = install_host.InstallConfig(
        public_ip="203.0.113.17",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        trusted_bundle_root=tmp_path / "bundle",
        python_executable=managed_python,
    )

    with pytest.raises(install_host.InstallError) as caught:
        install_host.collect_preflight(config, execute=install_host.real_executor)

    assert caught.value.code == "UNTRUSTED_PYTHON_ENVIRONMENT"


def test_production_setup_runs_real_hardened_helper_without_injected_callbacks(tmp_path: Path, monkeypatch) -> None:
    setup_tls = install_host.setup_tls
    config = setup_tls.SetupConfig(
        public_ip="203.0.113.17",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        hermes_group="hermes",
        staging=False,
        certificate_name="hermes-secure-env-work-203-0-113-17",
        certbot_executable=Path("/snap/bin/certbot"),
        python_executable=Path("/opt/hermes-secure-env/installer-venv/bin/python"),
        deploy_helper_source=tmp_path / "bundle" / "scripts" / "deploy_certificate.py",
        package_init_source=tmp_path / "bundle" / "secure_env_ingress" / "__init__.py",
        tls_helper_source=tmp_path / "bundle" / "secure_env_ingress" / "tls.py",
        helper_install_dir=tmp_path / "libexec" / "work",
        hook_install_path=tmp_path / "hooks" / "work",
        renewal_scheduler_verified=True,
    )
    commands: list[tuple[str, ...]] = []
    installs = []

    monkeypatch.setattr(setup_tls.os, "geteuid", lambda: 0)
    monkeypatch.setattr(setup_tls.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1000))
    monkeypatch.setattr(setup_tls.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=1000))
    monkeypatch.setattr(setup_tls, "validate_trusted_execution_path", lambda path: None)
    monkeypatch.setattr(setup_tls, "_validate_executable", lambda path: None)
    monkeypatch.setattr(setup_tls, "_validate_certbot_version", lambda path: None)
    monkeypatch.setattr(setup_tls, "_validate_trusted_directory", lambda path: None)
    monkeypatch.setattr(setup_tls, "_install_root_file", installs.append)

    def command_boundary(argv, **kwargs):
        commands.append(tuple(str(part) for part in argv))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(setup_tls.subprocess, "run", command_boundary)

    report = setup_tls.run_setup(config, apply=True, confirmation=setup_tls.CONFIRMATION)

    assert report.applied is True
    assert len(installs) == 4
    assert any("certonly" in command for command in commands)
    assert any(command[1:3] == ("renew", "--dry-run") for command in commands)
