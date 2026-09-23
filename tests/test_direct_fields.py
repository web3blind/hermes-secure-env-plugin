from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import yaml

from secure_env_ingress.command import (
    BOOTSTRAP_GUIDANCE,
    DIRECT_USAGE,
    CommandController,
    parse_request,
)
from secure_env_ingress.setup_config import (
    SetupConfigError,
    UnauthorizedOwnerError,
    define_named_profile,
)
from secure_env_ingress.writer import add_missing, bind_target


PLUGIN_ID = "secure-env-ingress"


def _request(text: str, user: int = 88):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user, is_bot=False),
        effective_chat=SimpleNamespace(type="private"),
        effective_message=SimpleNamespace(
            text=text, business_connection_id=None, reply_text=AsyncMock()
        ),
    )


def _home(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    existing_parent = home / "existing"
    existing_parent.mkdir(mode=0o700)
    existing_target = existing_parent / "original.env"
    existing_target.write_text('SENV_TEST_VALUE="preserve-me"\n', encoding="utf-8")
    existing_target.chmod(0o600)
    settings = {
        "public_ip": "203.0.113.10",
        "listen_host": "0.0.0.0",
        "listen_port": 18443,
        "cert_path": str(home / "cert.pem"),
        "key_path": str(home / "key.pem"),
        "safety_seconds": 86400,
        "ttl_seconds": 300,
        "allowed_telegram_user_ids": [88],
        "profiles": {
            "test": {
                "target_mode": "custom",
                "target_path": str(existing_target),
                "keys": ["SENV_TEST_VALUE"],
            }
        },
        "mini_app_enabled": False,
    }
    config = {
        "unrelated": {"preserve": True},
        "plugins": {
            "enabled": [PLUGIN_ID],
            "entries": {PLUGIN_ID: {"settings": settings}},
        },
    }
    path = home / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return home, existing_target


def _settings(home: Path) -> dict:
    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    return raw["plugins"]["entries"][PLUGIN_ID]["settings"]


def test_parser_preserves_posix_field_spelling_and_rejects_secret_shaped_input():
    request = parse_request("site_auth field1,Field_2,_third")
    assert request is not None
    assert request.profile == "site_auth"
    assert request.fields == ("field1", "Field_2", "_third")

    rejected = [
        "site_auth field=value",
        "site_auth field1,field1",
        "site_auth ../field",
        "site_auth field/one",
        "site_auth field1,,field2",
        "site_auth field1\nfield2",
        "setup extra",
        "status extra",
        "cancel extra",
        "site_auth " + ",".join(f"K{i}" for i in range(33)),
        "site_auth " + "x" * 129,
    ]
    for raw in rejected:
        assert parse_request(raw) is None


def test_define_new_profile_and_update_existing_preserve_targets_values_and_case(tmp_path):
    home, existing_target = _home(tmp_path)

    created = define_named_profile(home=home, owner=88, profile="site_auth", keys=("field1", "Field_2"))
    assert created.target == home / "secrets-ingress" / "site_auth.env"
    assert created.keys == ("field1", "Field_2")
    assert not created.target.exists()

    changed = define_named_profile(home=home, owner=88, profile="test", keys=("lowercase", "MixedCase"))
    assert changed.target == existing_target
    assert existing_target.read_text(encoding="utf-8") == 'SENV_TEST_VALUE="preserve-me"\n'
    settings = _settings(home)
    assert settings["profiles"]["site_auth"]["keys"] == ["field1", "Field_2"]
    assert settings["profiles"]["test"]["keys"] == ["lowercase", "MixedCase"]
    assert settings["profiles"]["test"]["target_path"] == str(existing_target)

    binding = bind_target(existing_target, expected_uid=os.getuid())
    add_missing(existing_target, {"lowercase": "new-value"}, binding=binding)
    contents = existing_target.read_text(encoding="utf-8")
    assert contents.count("SENV_TEST_VALUE=") == 1
    assert 'SENV_TEST_VALUE="preserve-me"' in contents
    assert "lowercase=" in contents


def test_define_profile_rechecks_owner_and_target_before_any_config_write(tmp_path):
    home, _ = _home(tmp_path)
    before = (home / "config.yaml").read_bytes()

    with pytest.raises(UnauthorizedOwnerError):
        define_named_profile(home=home, owner=99, profile="site_auth", keys=("field1",))
    assert (home / "config.yaml").read_bytes() == before
    assert not (home / "backups").exists()

    unsafe_parent = home / "secrets-ingress"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    unsafe_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SetupConfigError):
        define_named_profile(home=home, owner=88, profile="site_auth", keys=("field1",))
    assert (home / "config.yaml").read_bytes() == before
    assert not (home / "backups").exists()


@pytest.mark.parametrize("name", ["../escape", "nested/child", "setup", "invalid.name"])
def test_invalid_profile_never_creates_destination_directories(tmp_path, name):
    home, _ = _home(tmp_path)
    before = (home / "config.yaml").read_bytes()
    with pytest.raises(SetupConfigError):
        define_named_profile(home=home, owner=88, profile=name, keys=("field1",))
    assert not (home / "secrets-ingress").exists()
    assert not (home / "backups").exists()
    assert (home / "config.yaml").read_bytes() == before


class _Runtime:
    def __init__(self):
        self.calls = []

    def create(self, owner, name):
        self.calls.append(("create", owner, name))
        return {"url": "https://example.invalid/e#token", "web_app_url": None}

    def cancel(self, owner):
        self.calls.append(("cancel", owner))


@pytest.mark.asyncio
async def test_direct_command_defines_then_issues_form_without_echoing_values(tmp_path):
    runtime = _Runtime()
    definitions = []

    def define(owner, profile, fields):
        definitions.append((owner, profile, fields))
        return SimpleNamespace(target=tmp_path / "site_auth.env", keys=fields)

    update = _request("/senv site_auth field1,field2")
    controller = CommandController(
        runtime,
        frozenset({88}),
        profile_definer=define,
        profile_exists=lambda _name: False,
    )
    await controller.handle(update, None)

    assert definitions == [(88, "site_auth", ("field1", "field2"))]
    assert runtime.calls == [("create", 88, "site_auth")]
    reply = update.effective_message.reply_text.call_args.args[0]
    assert "field1, field2" in reply
    assert str(tmp_path / "site_auth.env") in reply


@pytest.mark.asyncio
async def test_unknown_profile_guidance_bootstrap_guidance_and_unauthorized_silence():
    runtime = _Runtime()
    unknown = _request("/senv missing")
    controller = CommandController(
        runtime,
        frozenset({88}),
        profile_exists=lambda _name: False,
    )
    await controller.handle(unknown, None)
    assert unknown.effective_message.reply_text.call_args.args == (DIRECT_USAGE,)
    assert runtime.calls == []

    bootstrap = _request("/senv site_auth field1,field2")
    controller = CommandController(
        runtime,
        frozenset(),
        setup_authorized=lambda owner: owner == 88,
    )
    await controller.handle(bootstrap, None)
    assert bootstrap.effective_message.reply_text.call_args.args == (BOOTSTRAP_GUIDANCE,)

    unauthorized = _request("/senv site_auth field1,field2", user=99)
    await controller.handle(unauthorized, None)
    unauthorized.effective_message.reply_text.assert_not_awaited()
