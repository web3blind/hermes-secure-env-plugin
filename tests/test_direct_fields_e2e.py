from __future__ import annotations

import asyncio
import hashlib
from itertools import count
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest
import telegram
import yaml
from dotenv import dotenv_values
from gateway.session import build_session_key
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest

from secure_env_ingress.plugin import register
from secure_env_ingress.runtime import IngressRuntime
from test_phase0_compatibility import _connected_telegram, _source, _telegram_update as _base_update
from test_runtime_e2e import make_runtime, post


PLUGIN_ID = "secure-env-ingress"
_ids = count(1000)


def _telegram_update(bot, text, **kwargs):
    raw = _base_update(bot, text, **kwargs).to_dict()
    raw["update_id"] = next(_ids)
    raw["message"]["message_id"] = next(_ids)
    return telegram.Update.de_json(raw, bot)


def _read_config(home: Path) -> dict:
    return yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))


def _write_runtime_config(home: Path, settings: dict) -> None:
    config = {
        "plugins": {
            "enabled": [PLUGIN_ID],
            "entries": {PLUGIN_ID: {"settings": settings}},
        }
    }
    path = home / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def _settings(home: Path) -> dict:
    return _read_config(home)["plugins"]["entries"][PLUGIN_ID]["settings"]


@pytest.mark.asyncio
async def test_native_direct_fields_persist_refresh_https_submit_and_replay(tmp_path, monkeypatch):
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings["allowed_telegram_user_ids"] = [88]
    settings["profiles"] = {
        "test": {"target_mode": "hermes", "keys": ["SENV_TEST_VALUE"]}
    }
    existing = home / ".env"
    existing.write_text('SENV_TEST_VALUE="preserve-me"\n', encoding="utf-8")
    existing.chmod(0o600)
    _write_runtime_config(home, settings)
    monkeypatch.setenv("HERMES_HOME", str(home))

    manager = PluginManager()
    ctx = PluginContext(
        manifest=PluginManifest(name=PLUGIN_ID, version="0.2.0"), manager=manager
    )
    replies = []

    async def reply(message, text, **kwargs):
        replies.append((text, kwargs))

    monkeypatch.setattr(telegram.Message, "reply_text", reply)

    def test_runtime(config, active_home, bot_token):
        return IngressRuntime(config, active_home, bot_token, trust_roots=root)

    monkeypatch.setattr("secure_env_ingress.runtime.IngressRuntime", test_runtime)

    def live_config():
        return _read_config(home)

    with patch("hermes_cli.plugins.load_config_readonly", side_effect=live_config):
        register(ctx)
        try:
            async with _connected_telegram(monkeypatch, manager) as (adapter, app):
                adapter._active_sessions[build_session_key(_source())] = asyncio.Event()

                await app.process_update(
                    _telegram_update(app.bot, "/senv site_auth field1,field2")
                )
                adapter._message_handler.assert_not_awaited()
                profile = _settings(home)["profiles"]["site_auth"]
                target = home / "secrets-ingress" / "site_auth.env"
                assert profile == {
                    "target_mode": "custom",
                    "target_path": str(target),
                    "keys": ["field1", "field2"],
                }
                assert not target.exists()
                url = replies[-1][1]["reply_markup"].inline_keyboard[0][0].url
                token = urlsplit(url).fragment
                status, schema = post(settings, root, "/session", {"token": token, "initData": ""})
                assert status == 200
                assert schema == {"label": "site_auth", "keys": ["field1", "field2"]}
                values = ["first-" + "a" * 10, "second-" + "b" * 10]
                status, result = post(
                    settings,
                    root,
                    "/submit",
                    {"token": token, "initData": "", "values": values},
                )
                assert status == 200 and result == {"added": ["field1", "field2"]}
                stored = dotenv_values(target, interpolate=False)
                assert hashlib.sha256(stored["field1"].encode()).digest() == hashlib.sha256(values[0].encode()).digest()
                assert hashlib.sha256(stored["field2"].encode()).digest() == hashlib.sha256(values[1].encode()).digest()
                replay_status, _ = post(
                    settings,
                    root,
                    "/submit",
                    {"token": token, "initData": "", "values": values},
                )
                assert replay_status == 410

                await app.process_update(
                    _telegram_update(app.bot, "/senv test lowercase,MixedCase")
                )

                changed = _settings(home)["profiles"]["test"]
                assert changed == {
                    "target_mode": "hermes",
                    "keys": ["lowercase", "MixedCase"],
                }
                second_url = replies[-1][1]["reply_markup"].inline_keyboard[0][0].url
                second_token = urlsplit(second_url).fragment
                status, schema = post(
                    settings, root, "/session", {"token": second_token, "initData": ""}
                )
                assert status == 200
                assert schema["keys"] == ["lowercase", "MixedCase"]
                status, _ = post(
                    settings,
                    root,
                    "/submit",
                    {
                        "token": second_token,
                        "initData": "",
                        "values": ["lower-value", "mixed-value"],
                    },
                )
                assert status == 200
                final = dotenv_values(existing, interpolate=False)
                assert final["SENV_TEST_VALUE"] == "preserve-me"
                assert final["lowercase"] == "lower-value"
                assert final["MixedCase"] == "mixed-value"
        finally:
            manager.unload()


@pytest.mark.asyncio
async def test_native_direct_fields_rejects_auth_metadata_injection_and_cross_profile(tmp_path, monkeypatch):
    sample, settings, home, _root = make_runtime(tmp_path)
    sample.close()
    settings["allowed_telegram_user_ids"] = [88]
    _write_runtime_config(home, settings)
    other = tmp_path / "other-home"
    other.mkdir(mode=0o700)
    (other / "config.yaml").write_text("unrelated: preserved\n", encoding="utf-8")
    (other / "config.yaml").chmod(0o600)
    other_before = (other / "config.yaml").read_bytes()
    monkeypatch.setenv("HERMES_HOME", str(home))

    manager = PluginManager()
    ctx = PluginContext(
        manifest=PluginManifest(name=PLUGIN_ID, version="0.2.0"), manager=manager
    )
    replies = []

    async def reply(message, text, **kwargs):
        replies.append(text)

    monkeypatch.setattr(telegram.Message, "reply_text", reply)
    with patch("hermes_cli.plugins.load_config_readonly", side_effect=lambda: _read_config(home)):
        register(ctx)
        monkeypatch.setenv("HERMES_HOME", str(other))
        try:
            async with _connected_telegram(monkeypatch, manager) as (adapter, app):
                adapter._active_sessions[build_session_key(_source())] = asyncio.Event()
                before = (home / "config.yaml").read_bytes()
                await app.process_update(
                    _telegram_update(app.bot, "/senv stolen secret=value", user_id=99)
                )
                await app.process_update(
                    _telegram_update(app.bot, "/senv stolen secret=value")
                )
                await app.process_update(
                    _telegram_update(
                        app.bot,
                        "/senv stolen field1,field2",
                        business=True,
                    )
                )
                assert adapter._message_handler.await_count == 0
                assert (home / "config.yaml").read_bytes() == before
                assert (other / "config.yaml").read_bytes() == other_before
                assert "secret=value" not in repr(replies)
        finally:
            manager.unload()
