from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from secure_env_ingress.setup_config import (
    SetupConfigError,
    check_configuration,
    configure,
)

PLUGIN_ID = "secure-env-ingress"


def _private_home(tmp_path: Path) -> Path:
    home = tmp_path / "hermes-home"
    home.mkdir(mode=0o700)
    return home


def _settings(config: dict) -> dict:
    return config["plugins"]["entries"][PLUGIN_ID]["settings"]


def test_configure_preserves_config_allowlist_profiles_and_makes_private_backup(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    config_path = home / "config.yaml"
    original = {
        "unknown_section": {"keep": [1, 2, 3]},
        "plugins": {
            "enabled": ["existing-plugin"],
            "entries": {
                PLUGIN_ID: {
                    "other_entry_metadata": "keep",
                    "settings": {
                        "allowed_telegram_user_ids": [17],
                        "profiles": {
                            "production": {
                                "target_mode": "custom",
                                "target_path": str(home / "production" / ".env"),
                                "keys": ["PRODUCTION_TOKEN"],
                            }
                        },
                    },
                },
                "other-plugin": {"settings": {"answer": 42}},
            },
        },
    }
    config_path.write_text(yaml.safe_dump(original, sort_keys=False), encoding="utf-8")
    config_path.chmod(0o600)

    report = configure(home=home, owner=23, public_ip="203.0.113.9")

    updated = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    settings = _settings(updated)
    assert updated["unknown_section"] == original["unknown_section"]
    assert updated["plugins"]["entries"]["other-plugin"] == original["plugins"]["entries"]["other-plugin"]
    assert updated["plugins"]["entries"][PLUGIN_ID]["other_entry_metadata"] == "keep"
    assert updated["plugins"]["enabled"] == ["existing-plugin", PLUGIN_ID]
    assert settings["allowed_telegram_user_ids"] == [17, 23]
    assert settings["profiles"]["production"] == original["plugins"]["entries"][PLUGIN_ID]["settings"]["profiles"]["production"]
    assert settings["profiles"]["test"] == {
        "target_mode": "custom",
        "target_path": str(home / "secrets-ingress" / "test.env"),
        "keys": ["SENV_TEST_VALUE"],
    }
    assert settings["cert_path"] == str(home / "secrets-ingress" / "tls" / "current" / "fullchain.pem")
    assert settings["key_path"] == str(home / "secrets-ingress" / "tls" / "current" / "privkey.pem")
    assert settings["safety_seconds"] == 86400
    assert settings["ttl_seconds"] == 300
    assert settings["mini_app_enabled"] is False
    assert report.changed is True
    assert report.backup_created is True
    assert report.config_valid is True
    assert report.target_safe is True
    assert report.tls_valid is False
    assert report.ready is False

    backups = list((home / "secrets-ingress" / "config-backups").glob("config.yaml.secure-env-setup.*"))
    assert len(backups) == 1
    backup = backups[0]
    assert yaml.safe_load(backup.read_text(encoding="utf-8")) == original
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((home / "secrets-ingress").stat().st_mode) == 0o700
    assert not (home / ".env").exists()
    assert not (home / "secrets-ingress" / "test.env").exists()


def test_configure_is_idempotent_and_never_touches_existing_dotenv(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    dotenv = home / ".env"
    dotenv.write_bytes(b"EXISTING_VALUE=preserve-me\n")
    dotenv.chmod(0o600)
    before = dotenv.stat()

    first = configure(home=home, owner=23, public_ip="203.0.113.9")
    backup_count = len(list((home / "secrets-ingress" / "config-backups").glob("*"))) if (home / "secrets-ingress" / "config-backups").exists() else 0
    second = configure(home=home, owner=23, public_ip="203.0.113.9")

    after = dotenv.stat()
    assert dotenv.read_bytes() == b"EXISTING_VALUE=preserve-me\n"
    assert (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
        before.st_size,
    )
    assert first.changed is True
    assert second.changed is False
    assert second.backup_created is False
    assert (len(list((home / "secrets-ingress" / "config-backups").glob("*"))) if (home / "secrets-ingress" / "config-backups").exists() else 0) == backup_count


def test_configure_rejects_conflicting_security_setting_without_mutation_or_backup(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    config_path = home / "config.yaml"
    raw = {
        "plugins": {
            "entries": {
                PLUGIN_ID: {
                    "settings": {"listen_port": 9443},
                }
            }
        }
    }
    before = yaml.safe_dump(raw, sort_keys=False)
    config_path.write_text(before, encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(SetupConfigError, match="conflicting existing security setting"):
        configure(home=home, owner=23, public_ip="203.0.113.9", port=18443)

    assert config_path.read_text(encoding="utf-8") == before
    assert not (home / "backups").exists()


def test_configure_never_replaces_conflicting_existing_profile(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    config_path = home / "config.yaml"
    raw = {
        "plugins": {
            "entries": {
                PLUGIN_ID: {
                    "settings": {
                        "profiles": {
                            "test": {
                                "target_mode": "custom",
                                "target_path": str(home / "different.env"),
                                "keys": ["SENV_TEST_VALUE"],
                            }
                        }
                    }
                }
            }
        }
    }
    before = yaml.safe_dump(raw, sort_keys=False)
    config_path.write_text(before, encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(SetupConfigError, match="existing profile conflicts"):
        configure(home=home, owner=23, public_ip="203.0.113.9")

    assert config_path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("contents", ["plugins: [", "- not-a-mapping\n"])
def test_existing_malformed_config_fails_closed(tmp_path: Path, contents: str) -> None:
    home = _private_home(tmp_path)
    config_path = home / "config.yaml"
    config_path.write_text(contents, encoding="utf-8")
    config_path.chmod(0o600)

    with pytest.raises(SetupConfigError, match="existing config is malformed"):
        configure(home=home, owner=23, public_ip="203.0.113.9")

    assert config_path.read_text(encoding="utf-8") == contents


@pytest.mark.parametrize("unsafe", ["symlink", "mode", "hardlink"])
def test_configure_rejects_unsafe_existing_config_file(tmp_path: Path, unsafe: str) -> None:
    home = _private_home(tmp_path)
    config_path = home / "config.yaml"
    source = tmp_path / "source.yaml"
    if unsafe == "symlink":
        source.write_text("{}\n", encoding="utf-8")
        source.chmod(0o600)
        config_path.symlink_to(source)
    else:
        config_path.write_text("{}\n", encoding="utf-8")
        config_path.chmod(0o644 if unsafe == "mode" else 0o600)
        if unsafe == "hardlink":
            os.link(config_path, tmp_path / "second-link")

    with pytest.raises(SetupConfigError, match="unsafe config file"):
        configure(home=home, owner=23, public_ip="203.0.113.9")


def test_configure_rejects_root_and_unsafe_home_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _private_home(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(SetupConfigError, match="non-root"):
        configure(home=home, owner=23, public_ip="203.0.113.9")

    monkeypatch.setattr(os, "geteuid", lambda: os.getuid())
    home.chmod(0o755)
    with pytest.raises(SetupConfigError, match="private directory"):
        configure(home=home, owner=23, public_ip="203.0.113.9")


def test_check_reports_structured_booleans_and_requires_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _private_home(tmp_path)
    configure(home=home, owner=23, public_ip="203.0.113.9")
    calls: list[tuple[Path, Path, str, int]] = []

    def valid_tls(cert, key, *, expected_ip, owner_uid, minimum_remaining):
        assert minimum_remaining.total_seconds() == 86400
        calls.append((Path(cert), Path(key), expected_ip, owner_uid))
        return object()

    monkeypatch.setattr("secure_env_ingress.setup_config.validate_certificate", valid_tls)
    report = check_configuration(home=home, owner=23, public_ip="203.0.113.9")

    assert report.as_dict() == {
        "backup_created": False,
        "changed": False,
        "config_file_secure": True,
        "config_valid": True,
        "ready": True,
        "target_safe": True,
        "tls_valid": True,
    }
    assert calls == [(
        home / "secrets-ingress" / "tls" / "current" / "fullchain.pem",
        home / "secrets-ingress" / "tls" / "current" / "privkey.pem",
        "203.0.113.9",
        os.getuid(),
    )]


def test_check_rejects_existing_target_with_unsafe_metadata(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    configure(home=home, owner=23, public_ip="203.0.113.9")
    target = home / "secrets-ingress" / "test.env"
    target.write_bytes(b"")
    target.chmod(0o644)

    report = check_configuration(home=home, owner=23, public_ip="203.0.113.9")
    assert report.config_valid is True
    assert report.target_safe is False
    assert report.ready is False


def test_cli_uses_profile_aware_home_supports_options_and_check_mode(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    tls_dir = home / "custom-tls"
    env = {**os.environ, "HERMES_HOME": str(home), "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    configured = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_env_ingress.setup_config",
            "configure",
            "--owner",
            "123456",
            "--public-ip",
            "203.0.113.11",
            "--profile",
            "smoke",
            "--keys",
            "SENV_SMOKE_ONE",
            "SENV_SMOKE_TWO",
            "--tls-dir",
            str(tls_dir),
            "--port",
            "19443",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stderr
    configured_json = json.loads(configured.stdout)
    assert configured_json["config_valid"] is True
    assert configured_json["ready"] is False
    assert all(type(value) is bool for value in configured_json.values())

    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    settings = _settings(raw)
    assert settings["listen_port"] == 19443
    assert settings["cert_path"] == str(tls_dir / "fullchain.pem")
    assert settings["profiles"]["smoke"]["keys"] == ["SENV_SMOKE_ONE", "SENV_SMOKE_TWO"]

    checked = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_env_ingress.setup_config",
            "check",
            "--owner",
            "123456",
            "--public-ip",
            "203.0.113.11",
            "--profile",
            "smoke",
            "--keys",
            "SENV_SMOKE_ONE",
            "SENV_SMOKE_TWO",
            "--tls-dir",
            str(tls_dir),
            "--port",
            "19443",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert checked.returncode == 1
    checked_json = json.loads(checked.stdout)
    assert checked_json["config_valid"] is True
    assert checked_json["tls_valid"] is False
    assert checked_json["ready"] is False
    assert all(type(value) is bool for value in checked_json.values())


@pytest.mark.parametrize("existing_config", [False, True])
@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "mode", "directory", "parent_symlink"])
def test_unsafe_target_rejected_before_config_mutation(tmp_path, unsafe, existing_config):
    home = _private_home(tmp_path)
    config = home / "config.yaml"
    original = b"model: preserved-model\n"
    if existing_config:
        config.write_bytes(original)
        config.chmod(0o600)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    source = outside / "test.env"
    source.write_bytes(b"TEST_ONLY=unchanged\n")
    source.chmod(0o600)
    parent = home / "secrets-ingress"
    if unsafe == "parent_symlink":
        parent.symlink_to(outside, target_is_directory=True)
    else:
        parent.mkdir(mode=0o700)
        target = parent / "test.env"
        if unsafe == "symlink":
            target.symlink_to(source)
        elif unsafe == "hardlink":
            os.link(source, target)
        elif unsafe == "directory":
            target.mkdir(mode=0o700)
        else:
            target.write_bytes(b"")
            target.chmod(0o644)
    with pytest.raises(SetupConfigError):
        configure(home=home, owner=23, public_ip="203.0.113.9")
    assert source.read_bytes() == b"TEST_ONLY=unchanged\n"
    assert not (home / "backups").exists()
    if existing_config:
        assert config.read_bytes() == original
    else:
        assert not config.exists()


def test_fresh_config_mode_under_permissive_umask(tmp_path):
    home = _private_home(tmp_path)
    old_umask = os.umask(0)
    try:
        report = configure(home=home, owner=23, public_ip="203.0.113.9")
    finally:
        os.umask(old_umask)
    assert report.config_file_secure and report.config_valid
    assert stat.S_IMODE((home / "config.yaml").stat().st_mode) == 0o600
    assert not (home / "secrets-ingress" / "test.env").exists()


def test_cli_rejects_non_numeric_owner_without_writing(tmp_path: Path) -> None:
    home = _private_home(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "secure_env_ingress.setup_config",
            "configure",
            "--home",
            str(home),
            "--owner",
            "not-numeric",
            "--public-ip",
            "203.0.113.11",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (home / "config.yaml").exists()
