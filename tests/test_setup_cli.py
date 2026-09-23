from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.setup_tls import (
    CONFIRMATION,
    SetupConfig,
    build_deploy_wrapper,
    build_root_installs,
    build_setup_commands,
    run_setup,
    validate_trusted_execution_path,
)


def config_for(tmp_path: Path, *, staging: bool = True) -> SetupConfig:
    sources = tmp_path / "sources"
    package = sources / "secure_env_ingress"
    package.mkdir(parents=True, exist_ok=True)
    deploy = sources / "deploy_certificate.py"
    init = package / "__init__.py"
    tls = package / "tls.py"
    deploy.write_text("# deploy\n", encoding="utf-8")
    init.write_text("", encoding="utf-8")
    tls.write_text("# tls\n", encoding="utf-8")
    return SetupConfig(
        public_ip="203.0.113.4",
        runtime_dir=tmp_path / "runtime",
        hermes_user="hermes",
        hermes_group="hermes",
        staging=staging,
        certbot_executable=Path("/opt/certbot/bin/certbot"),
        python_executable=Path("/usr/bin/python3"),
        deploy_helper_source=deploy,
        package_init_source=init,
        tls_helper_source=tls,
        helper_install_dir=tmp_path / "root" / "libexec",
        hook_install_path=tmp_path / "root" / "hooks" / "hermes-secure-env",
        trusted_source_root=tmp_path / "letsencrypt",
    )


def test_plan_requires_existing_certbot_instead_of_installing_or_changing_firewall(tmp_path):
    commands = build_setup_commands(config_for(tmp_path))
    flattened = [part for command in commands for part in command]
    assert "snap" not in flattened
    assert "apt" not in flattened
    assert "ufw" not in flattened
    assert any(command[0] == "/opt/certbot/bin/certbot" and "--staging" in command for command in commands)


def test_production_and_staging_have_distinct_issuance_and_dry_run_plans(tmp_path):
    staging = build_setup_commands(config_for(tmp_path, staging=True))
    production = build_setup_commands(config_for(tmp_path, staging=False))
    assert not any(command[:3] == ("/opt/certbot/bin/certbot", "renew", "--dry-run") for command in staging)
    assert any(command[:3] == ("/opt/certbot/bin/certbot", "renew", "--dry-run") for command in production)
    assert any("--staging" in command for command in staging if command[0] == "/opt/certbot/bin/certbot")
    assert not any("--staging" in command for command in production if "certonly" in command)


def test_generated_hook_uses_fixed_absolute_helper_and_deploy_arguments(tmp_path):
    config = config_for(tmp_path)
    wrapper = build_deploy_wrapper(config).decode("utf-8")
    helper = config.helper_install_dir / "deploy_certificate.py"
    assert f"'{config.python_executable}' '-E' '-s' '{helper}'" in wrapper
    assert "'--apply' '--confirm' 'DEPLOY-CERTIFICATE'" in wrapper
    assert f"'--source-certificate' '{config.lineage_dir / 'fullchain.pem'}'" in wrapper
    assert f"'--source-private-key' '{config.lineage_dir / 'privkey.pem'}'" in wrapper
    assert f"'--destination-root' '{config.runtime_dir}'" in wrapper
    assert "RENEWED_LINEAGE" not in wrapper.split("exec ", 1)[1]
    installs = build_root_installs(config)
    assert installs[-1].destination == config.hook_install_path
    assert installs[-1].content == build_deploy_wrapper(config)
    assert all(install.destination.is_absolute() for install in installs)


def test_trusted_execution_path_rejects_writable_ancestor(tmp_path):
    boundary = tmp_path / "trusted"
    parent = boundary / "bin"
    parent.mkdir(parents=True)
    executable = parent / "python3"
    executable.write_text("", encoding="utf-8")
    boundary.chmod(0o755)
    parent.chmod(0o775)
    executable.chmod(0o755)
    with pytest.raises(PermissionError, match="group/world writable"):
        validate_trusted_execution_path(executable, trusted_uid=os.getuid(), boundary=boundary)
    parent.chmod(0o755)
    validate_trusted_execution_path(executable, trusted_uid=os.getuid(), boundary=boundary)


def test_run_setup_is_plan_only_until_exact_confirmation_and_supports_injected_io(tmp_path):
    config = config_for(tmp_path)
    executed: list[tuple[str, ...]] = []
    installed = []
    report = run_setup(
        config,
        execute=lambda argv: executed.append(tuple(argv)),
        install=lambda item: installed.append(item),
    )
    assert report.applied is False
    assert executed == []
    assert installed == []
    with pytest.raises(PermissionError):
        run_setup(
            config,
            apply=True,
            confirmation="yes",
            execute=lambda argv: None,
            install=lambda item: None,
        )
    report = run_setup(
        config,
        apply=True,
        confirmation=CONFIRMATION,
        execute=lambda argv: executed.append(tuple(argv)),
        install=lambda item: installed.append(item),
    )
    assert report.applied is True
    assert tuple(executed) == report.commands
    assert tuple(installed) == report.installs


def test_apply_failure_never_reports_renewal_dry_run_as_executed(tmp_path):
    config = config_for(tmp_path, staging=False)

    def fail_on_dry_run(argv):
        if tuple(argv[:3]) == (str(config.certbot_executable), "renew", "--dry-run"):
            raise RuntimeError("dry run failed")

    with pytest.raises(RuntimeError, match="dry run failed"):
        run_setup(
            config,
            apply=True,
            confirmation=CONFIRMATION,
            execute=fail_on_dry_run,
            install=lambda item: None,
        )
