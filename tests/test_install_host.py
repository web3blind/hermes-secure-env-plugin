from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import install_host


class HostExecutor:
    """Stateful OS-boundary fake; it never invokes host package/system tools."""

    def __init__(
        self,
        *,
        os_systemd: bool = True,
        packages: dict[str, bool] | None = None,
        certbot: str = "missing",
        timer_loaded: bool = False,
        timer_enabled: bool = False,
        timer_active: bool = False,
        timer_unit: str = "snap.certbot.renew.timer",
        python_ready: bool = False,
    ) -> None:
        self.systemd = os_systemd
        self.packages = packages or {"snapd": True, "python3-venv": True}
        self.certbot = certbot
        self.timer_loaded = timer_loaded
        self.timer_enabled = timer_enabled
        self.timer_active = timer_active
        self.timer_unit = timer_unit
        self.python_ready = python_ready
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv):
        command = tuple(str(part) for part in argv)
        self.calls.append(command)
        executable = command[0]
        if executable == str(install_host.DPKG_QUERY):
            package = command[-1]
            installed = self.packages.get(package, False)
            return install_host.CommandResult(0 if installed else 1, "install ok installed" if installed else "")
        if command == (str(install_host.SYSTEMCTL), "show", "--property=Version", "--value"):
            return install_host.CommandResult(0 if self.systemd else 1, "252\n" if self.systemd else "")
        if executable == str(install_host.SYSTEMCTL) and len(command) >= 5 and command[1:4] == (
            "show",
            "--property=LoadState",
            "--value",
        ):
            unit = command[4]
            loaded = self.timer_loaded and unit == self.timer_unit
            return install_host.CommandResult(0, "loaded\n" if loaded else "not-found\n")
        if executable == str(install_host.SYSTEMCTL) and command[1:3] == ("is-enabled", "--quiet"):
            return install_host.CommandResult(0 if self.timer_enabled else 1)
        if executable == str(install_host.SYSTEMCTL) and command[1:3] == ("is-active", "--quiet"):
            return install_host.CommandResult(0 if self.timer_active else 3)
        if executable == str(install_host.SYSTEMCTL) and command[1:3] == ("enable", "--now"):
            if command[-1] == "snapd.socket":
                return install_host.CommandResult(0)
            self.timer_loaded = self.timer_enabled = self.timer_active = True
            return install_host.CommandResult(0)
        if executable == str(install_host.APT_GET):
            if "install" in command:
                for package in ("snapd", "python3-venv"):
                    if package in command:
                        self.packages[package] = True
            return install_host.CommandResult(0)
        if executable == str(install_host.INSTALL):
            return install_host.CommandResult(0)
        if executable == str(install_host.SYSTEM_PYTHON) and "venv" in command:
            self.python_ready = True
            return install_host.CommandResult(0)
        if executable == str(install_host.SNAP):
            self.certbot = "certbot 5.4.0"
            self.timer_loaded = self.timer_enabled = self.timer_active = True
            return install_host.CommandResult(0)
        if command[1:] == ("--version",):
            if self.certbot == "missing":
                return install_host.CommandResult(127)
            return install_host.CommandResult(0, self.certbot + "\n")
        if executable == str(install_host.DEFAULT_PYTHON):
            if "-m" in command and "pip" in command:
                self.python_ready = True
                return install_host.CommandResult(0)
            if command[-1] == install_host._PYTHON_VERIFY_CODE:
                return install_host.CommandResult(0 if self.python_ready else 127)
        raise AssertionError(f"unexpected command: {command}")


def make_config(tmp_path: Path, *, production: bool = False, profile: str = "default") -> install_host.InstallConfig:
    return install_host.InstallConfig(
        public_ip="203.0.113.17",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        hermes_group="hermes",
        trusted_bundle_root=tmp_path / "trusted-bundle",
        profile=profile,
        production=production,
    )


def preflight(config, executor, *, os_id="ubuntu", ports=()):
    return install_host.collect_preflight(
        config,
        execute=executor,
        os_release={"ID": os_id, "VERSION_ID": "24.04"},
        listening_ports=ports,
    )


def test_preflight_is_read_only_and_reports_installable_missing_prerequisites(tmp_path):
    executor = HostExecutor(packages={"snapd": False, "python3-venv": False})
    report = preflight(make_config(tmp_path), executor)

    assert report.ready_to_apply is True
    assert report.certbot_status == "missing"
    assert report.python_status == "missing"
    assert report.packages == {"snapd": False, "python3-venv": False}
    assert all("install" not in command[1:2] for command in executor.calls)
    assert not any(command[:2] == (str(install_host.APT_GET), "update") for command in executor.calls)
    assert not any(command[0] == str(install_host.SNAP) and "install" in command for command in executor.calls)


def test_clean_host_apply_provisions_fixed_root_venv_with_exact_dependencies(tmp_path):
    executor = HostExecutor(packages={"snapd": False, "python3-venv": False})
    config = make_config(tmp_path)
    report = preflight(config, executor)

    result = install_host.run_install(
        config,
        preflight=report,
        apply=True,
        confirmation=install_host.APPLY_CONFIRMATION,
        execute=executor,
        setup_runner=lambda *args, **kwargs: object(),
        trusted_apply=True,
    )

    assert (str(install_host.INSTALL), "-d", "-m", "0755", "-o", "root", "-g", "root", str(install_host.INSTALLER_VENV.parent)) in result.commands
    assert (str(install_host.SYSTEM_PYTHON), "-E", "-s", "-m", "venv", str(install_host.INSTALLER_VENV)) in result.commands
    pip_commands = [command for command in result.commands if command[:5] == (str(install_host.DEFAULT_PYTHON), "-E", "-s", "-m", "pip")]
    assert len(pip_commands) == 1
    assert pip_commands[0][-3:] == install_host.PINNED_PYTHON_PACKAGES


def test_custom_certbot_path_is_rejected_instead_of_borrowing_packaged_timer(tmp_path):
    config = install_host.InstallConfig(
        public_ip="203.0.113.17",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        trusted_bundle_root=tmp_path / "trusted-bundle",
        certbot_executable=Path("/opt/certbot/bin/certbot"),
    )

    with pytest.raises(install_host.InstallError) as caught:
        preflight(config, HostExecutor(certbot="certbot 5.4.1", timer_loaded=True))

    assert caught.value.code == "UNSUPPORTED_CERTBOT_PATH"


def test_apt_certbot_timer_does_not_verify_snap_certbot_scheduler(tmp_path):
    executor = HostExecutor(
        certbot="certbot 5.4.1",
        timer_loaded=True,
        timer_enabled=True,
        timer_active=True,
        timer_unit="certbot.timer",
        python_ready=True,
    )
    config = make_config(tmp_path)
    report = preflight(config, executor)

    assert report.renewal_unit is None
    with pytest.raises(install_host.InstallError) as caught:
        install_host.run_install(
            config,
            preflight=report,
            apply=True,
            confirmation=install_host.APPLY_CONFIRMATION,
            execute=executor,
            setup_runner=lambda *args, **kwargs: object(),
            trusted_apply=True,
        )
    assert caught.value.code == "RENEWAL_UNIT_MISSING"


@pytest.mark.parametrize(
    ("os_id", "systemd", "ports", "code"),
    [
        ("fedora", True, (), "OS_UNSUPPORTED"),
        ("ubuntu", False, (), "SYSTEMD_REQUIRED"),
        ("debian", True, (80,), "PORT_80_IN_USE"),
    ],
)
def test_fail_closed_preflight_has_typed_recovery_without_mutation(tmp_path, os_id, systemd, ports, code):
    executor = HostExecutor(os_systemd=systemd)
    report = preflight(make_config(tmp_path), executor, os_id=os_id, ports=ports)

    assert report.ready_to_apply is False
    assert code in {issue.code for issue in report.issues}
    assert all(issue.recovery for issue in report.issues)
    assert not any(command[0] in {str(install_host.APT_GET), str(install_host.SNAP)} for command in executor.calls)


def test_existing_old_certbot_is_a_hard_error_not_replaced(tmp_path):
    executor = HostExecutor(certbot="certbot 4.0.0", timer_loaded=True, timer_enabled=True, timer_active=True)
    report = preflight(make_config(tmp_path), executor)

    assert report.issues[0].code == "CERTBOT_UNSUPPORTED"
    with pytest.raises(install_host.InstallError, match="existing Certbot") as caught:
        install_host.run_install(
            make_config(tmp_path),
            preflight=report,
            apply=True,
            confirmation=install_host.APPLY_CONFIRMATION,
            execute=executor,
            trusted_apply=True,
        )
    assert caught.value.code == "CERTBOT_UNSUPPORTED"
    assert not any(command[0] == str(install_host.SNAP) for command in executor.calls)


def test_apply_requires_exact_confirmation_before_any_write(tmp_path):
    executor = HostExecutor()
    config = make_config(tmp_path)
    report = preflight(config, executor)
    before = list(executor.calls)

    with pytest.raises(install_host.InstallError) as caught:
        install_host.run_install(config, preflight=report, apply=True, confirmation="yes", execute=executor, trusted_apply=True)

    assert caught.value.code == "CONFIRMATION_REQUIRED"
    assert executor.calls == before


def test_production_requires_separate_consent_before_any_write(tmp_path):
    executor = HostExecutor()
    config = make_config(tmp_path, production=True)
    report = preflight(config, executor)
    before = list(executor.calls)

    with pytest.raises(install_host.InstallError) as caught:
        install_host.run_install(
            config,
            preflight=report,
            apply=True,
            confirmation=install_host.APPLY_CONFIRMATION,
            execute=executor,
            trusted_apply=True,
        )

    assert caught.value.code == "PRODUCTION_CONSENT_REQUIRED"
    assert executor.calls == before


def test_missing_packages_and_certbot_are_installed_then_verified_and_tls_is_staging_first(tmp_path):
    executor = HostExecutor(packages={"snapd": False, "python3-venv": False})
    config = make_config(tmp_path, production=True, profile="work")
    report = preflight(config, executor)
    tls_calls = []

    def setup_runner(config, **kwargs):
        tls_calls.append((config, kwargs))
        return object()

    result = install_host.run_install(
        config,
        preflight=report,
        apply=True,
        confirmation=install_host.APPLY_CONFIRMATION,
        production_consent=install_host.PRODUCTION_CONSENT,
        execute=executor,
        setup_runner=setup_runner,
        trusted_apply=True,
    )

    assert result.applied and result.production_applied
    assert (str(install_host.APT_GET), "update") in result.commands
    assert (
        str(install_host.APT_GET),
        "install",
        "--yes",
        "--no-install-recommends",
        "snapd",
        "python3-venv",
    ) in result.commands
    assert (str(install_host.SNAP), "install", "certbot", "--classic") in result.commands
    assert [call[0].staging for call in tls_calls] == [True, False]
    assert all(call[1]["confirmation"] == install_host.setup_tls.CONFIRMATION for call in tls_calls)
    assert tls_calls[0][0].effective_certificate_name.endswith("-staging")
    assert tls_calls[1][0].effective_certificate_name == config.certificate_name
    assert tls_calls[0][0].hook_install_path.name == "hermes-secure-env-work"
    assert tls_calls[0][0].helper_install_dir == Path("/usr/local/libexec/hermes-secure-env/work")
    assert tls_calls[0][0].deploy_helper_source == config.trusted_bundle_root / "scripts" / "deploy_certificate.py"


def test_existing_verified_certbot_skips_snap_and_repairs_renewal_timer(tmp_path):
    executor = HostExecutor(certbot="certbot 5.4.1", timer_loaded=True, timer_enabled=False, timer_active=False)
    config = make_config(tmp_path)
    report = preflight(config, executor)
    tls_calls = []

    result = install_host.run_install(
        config,
        preflight=report,
        apply=True,
        confirmation=install_host.APPLY_CONFIRMATION,
        execute=executor,
        setup_runner=lambda config, **kwargs: tls_calls.append(config),
        trusted_apply=True,
    )

    assert result.renewal_unit == "snap.certbot.renew.timer"
    assert not any(command[0] == str(install_host.SNAP) for command in result.commands)
    assert (str(install_host.SYSTEMCTL), "enable", "--now", "snap.certbot.renew.timer") in executor.calls
    assert len(tls_calls) == 1 and tls_calls[0].staging is True


def test_missing_renewal_timer_fails_before_acme_setup(tmp_path):
    executor = HostExecutor(certbot="certbot 5.4.1", timer_loaded=False)
    config = make_config(tmp_path)
    report = preflight(config, executor)
    tls_calls = []

    with pytest.raises(install_host.InstallError) as caught:
        install_host.run_install(
            config,
            preflight=report,
            apply=True,
            confirmation=install_host.APPLY_CONFIRMATION,
            execute=executor,
            setup_runner=lambda *args, **kwargs: tls_calls.append(args),
            trusted_apply=True,
        )

    assert caught.value.code == "RENEWAL_UNIT_MISSING"
    assert tls_calls == []


def test_profile_paths_and_lineages_are_isolated(tmp_path):
    first = make_config(tmp_path, profile="default")
    second = make_config(tmp_path, profile="work")

    assert first.helper_install_dir != second.helper_install_dir
    assert first.hook_install_path != second.hook_install_path
    assert first.certificate_name != second.certificate_name
    assert install_host._tls_config(first, staging=True).effective_certificate_name != install_host._tls_config(first, staging=False).effective_certificate_name


def test_real_executor_uses_absolute_command_sanitized_environment(monkeypatch):
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(install_host.subprocess, "run", fake_run)
    monkeypatch.setattr(install_host.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker.so")

    result = install_host.real_executor(("/usr/bin/true",))

    assert result.returncode == 0
    assert observed["command"] == ("/usr/bin/true",)
    assert observed["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"}
    assert observed["cwd"] == "/"
    assert observed["shell"] is False


def test_real_executor_rejects_untrusted_privileged_executable_before_subprocess(tmp_path, monkeypatch):
    executable = tmp_path / "attacker-tool"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(install_host.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        install_host.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("untrusted executable reached subprocess.run"),
    )

    with pytest.raises(install_host.InstallError) as caught:
        install_host.real_executor((str(executable),))

    assert caught.value.code == "UNTRUSTED_EXECUTABLE"


def test_apply_rejects_untrusted_bundle_without_trusted_apply_bypass(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    config.trusted_bundle_root.mkdir()
    executor = HostExecutor()
    report = preflight(config, executor)
    before = list(executor.calls)
    monkeypatch.setattr(install_host.os, "geteuid", lambda: 0)

    with pytest.raises(install_host.InstallError) as caught:
        install_host.run_install(
            config,
            preflight=report,
            apply=True,
            confirmation=install_host.APPLY_CONFIRMATION,
            execute=executor,
        )

    assert caught.value.code == "UNTRUSTED_BUNDLE"
    assert executor.calls == before


def test_default_delegation_runs_real_setup_tls_without_injected_callbacks(tmp_path, monkeypatch):
    executor = HostExecutor(
        certbot="certbot 5.4.1",
        timer_loaded=True,
        timer_enabled=True,
        timer_active=True,
        python_ready=True,
    )
    config = make_config(tmp_path)
    report = preflight(config, executor)
    setup_commands = []

    monkeypatch.setattr(install_host.os, "geteuid", lambda: 0)
    monkeypatch.setattr(install_host, "_require_trusted_bundle", lambda config: None)
    monkeypatch.setattr(install_host, "_validate_managed_venv", lambda **kwargs: None)
    monkeypatch.setattr(install_host.setup_tls, "_validate_default_prerequisites", lambda config, installs: None)

    def command_boundary(command, **kwargs):
        setup_commands.append((tuple(command), kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(install_host.setup_tls.subprocess, "run", command_boundary)

    result = install_host.run_install(
        config,
        preflight=report,
        apply=True,
        confirmation=install_host.APPLY_CONFIRMATION,
        execute=executor,
    )

    assert result.applied is True
    assert len(setup_commands) == 1
    assert setup_commands[0][0][0] == str(install_host.DEFAULT_CERTBOT)
    assert "certonly" in setup_commands[0][0]
    assert setup_commands[0][1]["shell"] is False


def test_cli_help_and_bad_arguments_use_real_subprocess():
    script = Path(install_host.__file__).resolve()
    root = script.parents[1]
    environment = dict(os.environ, PYTHONPATH=str(root))

    help_result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    bad_result = subprocess.run(
        [sys.executable, str(script), "--apply"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert help_result.returncode == 0
    assert "PRIVILEGED-HOST-INSTALL" in help_result.stdout
    assert "ISSUE-PRODUCTION-CERTIFICATE" in help_result.stdout
    assert bad_result.returncode == 2
    assert "--public-ip" in bad_result.stderr
