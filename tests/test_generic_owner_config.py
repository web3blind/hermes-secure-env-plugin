"""Security regressions for platform-scoped owners and non-Telegram setup."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from secure_env_ingress.config import ConfigError, configured_owners, owner_identity
from secure_env_ingress.setup_config import (
    UnauthorizedOwnerError,
    configure,
    define_named_profile,
)

PLUGIN_ID = "secure-env-ingress"
PUBLIC_IP = "203.0.113.42"
OWNER = ("discord", "opaque-user:A")


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "hermes-home"
    home.mkdir(mode=0o700)
    return home


def _settings(home: Path) -> dict:
    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    return config["plugins"]["entries"][PLUGIN_ID]["settings"]


def test_owner_identities_are_platform_scoped_and_legacy_telegram_is_numeric() -> None:
    assert owner_identity("discord", "opaque-user:A") == OWNER
    assert owner_identity("discord", "123") != owner_identity("telegram", "123")
    assert configured_owners({
        "allowed_owners": {"discord": ["opaque-user:A", "123"], "telegram": ["123"]},
        "allowed_telegram_user_ids": [17],
    }) == {OWNER, ("discord", "123"), ("telegram", "123"), ("telegram", "17")}


@pytest.mark.parametrize("platform,user_id", [
    ("*", "opaque-user:A"), ("Discord", "opaque-user:A"),
    ("discord ", "opaque-user:A"), ("discord", ""),
    ("discord", " opaque-user:A"), ("discord", "opaque-user:A "),
    ("discord", "*"),
    ("discord", "user\nother"), ("discord", 123), ("discord", "a" * 257),
])
def test_owner_identity_rejects_noncanonical_or_broad_identity(platform: object, user_id: object) -> None:
    assert owner_identity(platform, user_id) is None


@pytest.mark.parametrize("raw", [
    {},
    {"allowed_owners": {"discord": ["same", "same"]}},
    {"allowed_owners": {"telegram": ["17"]}, "allowed_telegram_user_ids": [17]},
    {"allowed_telegram_user_ids": [17, 17]},
    {"allowed_telegram_user_ids": ["17"]},
    {"allowed_telegram_user_ids": [True]},
    {"allowed_telegram_user_ids": [0]},
    {"allowed_owners": {"discord": ["*"]}},
    {"allowed_owners": {"*": ["user"]}},
    {"allowed_owners": {"discord": [" user"]}},
    {"allowed_owners": {"discord": []}},
])
def test_configured_owners_rejects_ambiguous_or_missing_authorization(raw: dict) -> None:
    with pytest.raises(ConfigError):
        configured_owners(raw)


def test_configure_merges_generic_owner_without_telegram_or_unrelated_changes(tmp_path: Path) -> None:
    home = _home(tmp_path)
    path = home / "config.yaml"
    initial = {
        "model": "preserved-model",
        "plugins": {
            "enabled": ["existing-plugin"],
            "entries": {"existing-plugin": {"settings": {"keep": "unchanged"}}},
        },
    }
    path.write_text(yaml.safe_dump(initial), encoding="utf-8")
    path.chmod(0o600)

    report = configure(home=home, owner=OWNER, public_ip=PUBLIC_IP)

    saved = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert saved["model"] == initial["model"]
    assert saved["plugins"]["entries"]["existing-plugin"] == initial["plugins"]["entries"]["existing-plugin"]
    assert saved["plugins"]["enabled"] == ["existing-plugin", PLUGIN_ID]
    settings = _settings(home)
    assert settings["allowed_owners"] == {"discord": ["opaque-user:A"]}
    assert settings.get("allowed_telegram_user_ids", []) == []
    assert settings["profiles"]["test"] == {
        "target_mode": "custom",
        "target_path": str(home / "secrets-ingress" / "test.env"),
        "keys": ["SENV_TEST_VALUE"],
    }
    assert report.changed and report.backup_created and report.config_valid and report.target_safe
    assert not (home / "secrets-ingress" / "test.env").exists()


def test_cli_platform_configures_fresh_non_telegram_home(tmp_path: Path) -> None:
    home = _home(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-m", "secure_env_ingress.setup_config", "configure",
         "--home", str(home), "--platform", "discord", "--owner", "opaque-user:A",
         "--public-ip", PUBLIC_IP],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "HERMES_HOME": str(home)},
        text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["config_valid"] is True
    assert _settings(home)["allowed_owners"] == {"discord": ["opaque-user:A"]}
    assert _settings(home).get("allowed_telegram_user_ids", []) == []


@pytest.mark.parametrize("wrong_owner", [("telegram", "opaque-user:A"), ("slack", "opaque-user:A")])
def test_define_named_profile_rejects_wrong_platform_without_touching_target(
    tmp_path: Path, wrong_owner: tuple[str, str],
) -> None:
    home = _home(tmp_path)
    configure(home=home, owner=OWNER, public_ip=PUBLIC_IP)
    target = home / "secrets-ingress" / "test.env"
    target.write_bytes(b"EXISTING=untouched\n")
    target.chmod(0o600)
    before_target = target.stat()
    path = home / "config.yaml"
    before_config = path.read_bytes()
    backups = home / "secrets-ingress" / "config-backups"
    before_backups = set(backups.iterdir()) if backups.exists() else set()

    with pytest.raises(UnauthorizedOwnerError):
        define_named_profile(home=home, owner=wrong_owner, profile="test", keys=["NEW_KEY"])

    after_target = target.stat()
    assert target.read_bytes() == b"EXISTING=untouched\n"
    assert (after_target.st_ino, after_target.st_mtime_ns) == (before_target.st_ino, before_target.st_mtime_ns)
    assert path.read_bytes() == before_config
    assert (set(backups.iterdir()) if backups.exists() else set()) == before_backups
    assert _settings(home)["profiles"]["test"]["keys"] == ["SENV_TEST_VALUE"]


def test_generic_owner_can_redefine_fields_without_overwriting_existing_target(tmp_path: Path) -> None:
    home = _home(tmp_path)
    configure(home=home, owner=OWNER, public_ip=PUBLIC_IP)
    target = home / "secrets-ingress" / "test.env"
    target.write_bytes(b"EXISTING=unchanged\n")
    target.chmod(0o600)
    before = target.stat()

    defined = define_named_profile(home=home, owner=OWNER, profile="test", keys=["NEW_KEY"])

    after = target.stat()
    assert defined.target == target
    assert defined.keys == ("NEW_KEY",)
    assert _settings(home)["profiles"]["test"]["target_path"] == str(target)
    assert _settings(home)["profiles"]["test"]["keys"] == ["NEW_KEY"]
    assert target.read_bytes() == b"EXISTING=unchanged\n"
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


def test_backup_stays_private_when_unrelated_hermes_backups_is_public(tmp_path: Path) -> None:
    home = _home(tmp_path)
    unrelated = home / "backups"
    unrelated.mkdir(mode=0o755)
    unrelated.chmod(0o755)
    path = home / "config.yaml"
    original = b"model: preserved-model\n"
    path.write_bytes(original)
    path.chmod(0o600)

    report = configure(home=home, owner=OWNER, public_ip=PUBLIC_IP)

    private = home / "secrets-ingress" / "config-backups"
    backups = list(private.glob("config.yaml.secure-env-setup.*"))
    assert report.backup_created
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    assert stat.S_IMODE(unrelated.stat().st_mode) == 0o755
    assert list(unrelated.iterdir()) == []
