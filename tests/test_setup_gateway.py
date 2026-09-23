"""End-to-end setup handoff tests across plugin, PTB, and gateway routing."""
from __future__ import annotations

import asyncio
import json
from itertools import count
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.session import SessionSource, SessionStore, build_session_key
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from secure_env_ingress.plugin import register
from secure_env_ingress.setup_handoff import SETUP_BUTTON, SETUP_REQUEST

telegram = pytest.importorskip("telegram")
from telegram import ReplyKeyboardMarkup, Update  # noqa: E402
from telegram.request import BaseRequest  # noqa: E402


class _NoNetwork(BaseRequest):
    @property
    def read_timeout(self):
        return 1

    async def initialize(self):
        pass

    async def shutdown(self):
        pass

    async def do_request(self, url, method, request_data=None, **kwargs):
        endpoint = url.rsplit("/", 1)[-1]
        assert endpoint == "getMe", f"unexpected Telegram network call: {endpoint}"
        return 200, json.dumps({
            "ok": True,
            "result": {
                "id": 111,
                "is_bot": True,
                "first_name": "Offline",
                "username": "offline_bot",
            },
        }).encode()


def _write_config(home: Path, *, owners=(88,), injection=True):
    settings = {}
    if owners is not None:
        settings["allowed_telegram_user_ids"] = list(owners)
    entry = {"settings": settings}
    if injection is not None:
        entry["allow_gateway_injection"] = injection
    (home / "config.yaml").write_text(yaml.safe_dump({
        "plugins": {"entries": {"secure-env-ingress": entry}},
    }), encoding="utf-8")


def _manager(monkeypatch, home: Path) -> tuple[PluginManager, PluginContext]:
    from hermes_cli import plugins as plugins_mod

    monkeypatch.setenv("HERMES_HOME", str(home))
    manager = PluginManager(scope_key=str(home))
    context = PluginContext(
        PluginManifest(
            name="secure-env-ingress",
            key="secure-env-ingress",
            version="0.2.0",
            source="user",
        ),
        manager,
    )
    monkeypatch.setattr(plugins_mod, "_plugin_manager", manager)
    register(context)
    return manager, context


_ids = count(500)


def _update(bot, text: str, *, user_id=88, reply_secret: str | None = None) -> Update:
    message = {
        "message_id": next(_ids),
        "date": 1800000000,
        "chat": {"id": 42, "type": "private"},
        "from": {"id": user_id, "is_bot": False, "first_name": "Human"},
        "text": text,
    }
    if text.startswith("/senv"):
        message["entities"] = [{
            "type": "bot_command", "offset": 0, "length": len("/senv"),
        }]
    if reply_secret is not None:
        message["reply_to_message"] = {
            "message_id": 471,
            "date": 1799999999,
            "chat": {"id": 42, "type": "private"},
            "from": {"id": 88, "is_bot": False, "first_name": "Human"},
            "text": reply_secret,
            "photo": [{
                "file_id": "secret-photo", "file_unique_id": "secret-photo-u",
                "width": 1, "height": 1, "file_size": 1,
            }],
        }
    return Update.de_json({"update_id": next(_ids), "message": message}, bot)


@asynccontextmanager
async def _connected_telegram(monkeypatch, manager):
    from plugins.platforms.telegram.adapter import TelegramAdapter

    adapter = TelegramAdapter(PlatformConfig(
        enabled=True, token="111:offline-test", extra={"allowed_users": ["88"]},
    ))
    monkeypatch.setenv("TELEGRAM_WEBHOOK_URL", "")
    monkeypatch.setattr(
        adapter, "_build_ptb_requests", AsyncMock(return_value=(_NoNetwork(), _NoNetwork())),
    )
    monkeypatch.setattr(adapter, "_start_polling_mode", AsyncMock())
    monkeypatch.setattr(adapter, "_start_post_connect_housekeeping", lambda: None)
    monkeypatch.setattr(adapter, "_restart_task_attr", lambda _name, coro: coro.close())
    monkeypatch.setattr(adapter, "_write_runtime_status_safe", lambda *a, **kw: None)
    monkeypatch.setattr(adapter, "_set_status_indicator", AsyncMock())
    assert await adapter.connect()
    try:
        yield adapter, adapter._app
    finally:
        await adapter.disconnect()


def _source() -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        user_id="88",
        chat_id="42",
        user_name="Human",
        chat_type="dm",
    )


def _gateway(tmp_path: Path, adapter, manager: PluginManager, *, authorized=True):
    store = SessionStore(sessions_dir=tmp_path / "sessions", config=GatewayConfig())
    entry = store.get_or_create_session(_source())
    runner = object.__new__(GatewayRunner)
    runner.session_store = store
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._profile_adapters = {}
    runner._gateway_loop = asyncio.get_running_loop()
    runner._running = True
    runner._draining = False
    runner._background_tasks = set()
    runner._queued_events = {}
    runner._is_user_authorized = lambda _source, **_kwargs: authorized
    adapter.set_busy_session_handler(runner._handle_active_session_busy_message)
    runner._install_plugin_message_injector()
    return runner, entry


async def _wait_gateway_dispatch(runner):
    for _ in range(20):
        tasks = list(runner._background_tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0)
        if not runner._background_tasks:
            return
    raise AssertionError("gateway injection did not settle")


def _capture_replies(monkeypatch):
    replies = []

    async def reply_text(_message, text, **kwargs):
        replies.append((text, kwargs))

    monkeypatch.setattr(telegram.Message, "reply_text", reply_text)
    return replies


@pytest.mark.asyncio
@pytest.mark.parametrize("busy", [False, True], ids=["idle", "busy-fifo"])
async def test_setup_handoff_routes_exact_sanitized_request_through_gateway(
    tmp_path, monkeypatch, busy,
):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    _write_config(home)
    manager, _context = _manager(monkeypatch, home)
    # Registration is profile-bound even if ambient process selection changes later.
    other_home = tmp_path / "other-profile"
    other_home.mkdir(mode=0o700)
    _write_config(other_home, owners=(999,), injection=False)
    monkeypatch.setenv("HERMES_HOME", str(other_home))
    replies = _capture_replies(monkeypatch)
    secret = "TOP_SECRET_REPLY_VALUE"

    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        delivered = []
        delivered_event = asyncio.Event()

        async def on_message(event):
            delivered.append(event)
            delivered_event.set()
            return None

        adapter.set_message_handler(on_message)
        runner, entry = _gateway(tmp_path, adapter, manager)
        key = entry.session_key
        assert key == build_session_key(_source())
        human = MessageEvent(
            text="human follow-up containing " + secret,
            message_type=MessageType.PHOTO,
            source=_source(),
            media_urls=["private-photo.jpg"],
            media_types=["image/jpeg"],
            reply_to_text=secret,
            raw_message={"secret": secret},
        )
        if busy:
            adapter._active_sessions[key] = asyncio.Event()
            adapter._pending_messages[key] = human

        await app.process_update(_update(app.bot, "/senv setup", reply_secret=secret))
        await _wait_gateway_dispatch(runner)

        if busy:
            assert adapter._pending_messages[key] is human
            assert runner._queued_events[key][0].text == SETUP_REQUEST
            event = runner._queued_events[key][0]
            assert delivered == []
        else:
            await asyncio.wait_for(delivered_event.wait(), timeout=1)
            event = delivered[0]

        assert event.text == SETUP_REQUEST
        assert secret not in event.text
        assert event.raw_message is None
        assert event.reply_to_text is None
        assert event.reply_to_message_id is None
        assert event.media_urls == []
        assert event.media_types == []
        assert event.internal is True
        assert event.allow_gateway_control is False
        assert event.metadata["hermes_plugin_id"] == "secure-env-ingress"
        assert event.metadata["gateway_session_key"] == key
        assert len(replies) == 1
        assert "queued" in replies[0][0]
        runner._clear_plugin_message_injector()


@pytest.mark.asyncio
async def test_unauthorized_setup_is_silently_rejected_before_handoff(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    _write_config(home, owners=(88,))
    manager, _context = _manager(monkeypatch, home)
    replies = _capture_replies(monkeypatch)

    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        adapter.set_message_handler(AsyncMock(side_effect=AssertionError("fell through to gateway")))
        runner, _entry = _gateway(tmp_path, adapter, manager)
        await app.process_update(_update(app.bot, "/senv setup", user_id=99))
        await asyncio.sleep(0)
        assert replies == []
        assert runner._background_tasks == set()
        adapter._message_handler.assert_not_awaited()
        runner._clear_plugin_message_injector()


@pytest.mark.asyncio
async def test_bootstrap_owner_comes_only_from_numeric_profile_env(tmp_path, monkeypatch):
    # bootstrap_owner_ids intentionally rejects pytest's group-writable /var/tmp
    # ancestry. A private child of sticky, root-owned /tmp is a valid profile.
    with tempfile.TemporaryDirectory(dir="/tmp") as raw_home:
        home = Path(raw_home)
        home.chmod(0o700)
        _write_config(home, owners=None, injection=False)
        env_file = home / ".env"
        env_file.write_text(
            "TELEGRAM_ALLOWED_USERS=88\nUNRELATED_SECRET=never-forward\n", encoding="utf-8",
        )
        env_file.chmod(0o600)
        monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "999")
        manager, _context = _manager(monkeypatch, home)
        replies = _capture_replies(monkeypatch)

        async with _connected_telegram(monkeypatch, manager) as (_adapter, app):
            await app.process_update(_update(app.bot, "/senv setup", user_id=88))
            await app.process_update(_update(app.bot, "/senv setup", user_id=999))

        assert len(replies) == 1
        assert "Tap the setup button" in replies[0][0]
        assert "never-forward" not in replies[0][0]


@pytest.mark.asyncio
async def test_denied_injection_falls_back_to_user_authored_button_without_self_grant(
    tmp_path, monkeypatch,
):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    _write_config(home, injection=False)
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "88")
    manager, context = _manager(monkeypatch, home)
    replies = _capture_replies(monkeypatch)

    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        normal_turns = []
        normal_seen = asyncio.Event()

        async def on_message(event):
            normal_turns.append(event)
            normal_seen.set()
            return None

        adapter.set_message_handler(on_message)
        runner, entry = _gateway(tmp_path, adapter, manager)
        await app.process_update(_update(app.bot, "/senv setup"))
        await asyncio.sleep(0)

        assert runner._background_tasks == set()
        assert len(replies) == 1
        text, kwargs = replies[0]
        assert "Tap the setup button" in text
        markup = kwargs["reply_markup"]
        assert isinstance(markup, ReplyKeyboardMarkup)
        assert markup.keyboard[0][0].text == SETUP_BUTTON
        assert context.inject_message(SETUP_REQUEST, session_key=entry.session_key) is False

        button_update = _update(app.bot, SETUP_BUTTON)
        assert adapter._is_user_authorized_from_message(button_update.effective_message)
        assert adapter._should_process_message(button_update.effective_message)
        await app.process_update(button_update)
        try:
            await asyncio.wait_for(normal_seen.wait(), timeout=2)
        except TimeoutError:
            raise AssertionError({
                'drop': adapter._should_drop_delayed_delivery(),
                'pending': list(adapter._pending_text_batches),
                'tasks': list(adapter._pending_text_batch_tasks),
                'active': list(adapter._active_sessions),
            }) from None
        turn = normal_turns[0]
        assert turn.text == SETUP_BUTTON
        assert turn.internal is False
        assert turn.raw_message is not None
        assert turn.metadata.get("hermes_plugin_injection") is not True
        assert context.inject_message(SETUP_REQUEST, session_key=entry.session_key) is False
        runner._clear_plugin_message_injector()


@pytest.mark.asyncio
async def test_paused_setup_refuses_without_injection_or_button(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    _write_config(home)
    (home / "ESTOP").write_text("{}\n", encoding="utf-8")
    manager, _context = _manager(monkeypatch, home)
    replies = _capture_replies(monkeypatch)

    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        runner, _entry = _gateway(tmp_path, adapter, manager)
        await app.process_update(_update(app.bot, "/senv setup"))
        assert replies == [("Hermes is paused. Resume it before starting installation.", {})]
        assert runner._background_tasks == set()
        runner._clear_plugin_message_injector()


def test_register_exposes_setup_skill_to_real_skill_view(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    _write_config(home)
    manager, _context = _manager(monkeypatch, home)
    from tools.skills_tool import skill_view

    path = manager.find_plugin_skill("secure-env-ingress:setup")
    result = json.loads(skill_view("secure-env-ingress:setup"))

    assert path == Path(__file__).resolve().parents[1] / "secure_env_ingress" / "setup" / "SKILL.md"
    assert result["success"] is True
    assert result["name"] == "secure-env-ingress:setup"
    assert "Installation-only assistance" in result["content"]
