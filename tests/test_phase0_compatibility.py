"""Phase 0 probes against the real Hermes gateway and Telegram boundaries.

These are compatibility tests, not the secure-env ingress implementation.  They
must remain safe to run offline: no real token, service, port, or secret write.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from secure_env_ingress_probe import (  # noqa: E402
    PROBE_URL,
    SAFE_REPLY,
    build_telegram_markup,
    pre_gateway_dispatch,
    register,
)

from gateway.config import GatewayConfig, Platform, PlatformConfig  # noqa: E402
from gateway.platforms.base import BasePlatformAdapter, SendResult  # noqa: E402
from gateway.platforms.event import MessageEvent, MessageType  # noqa: E402
from gateway.session import SessionEntry, SessionSource, build_session_key  # noqa: E402
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest  # noqa: E402

telegram = pytest.importorskip("telegram")
from telegram import Update  # noqa: E402
from telegram.request import BaseRequest  # noqa: E402


FIXTURE_ARGUMENT = "fixture-profile"
FIXTURE_ASSIGNMENT = "PROBE_KEY=fixture-value-never-echo"


class _NoNetwork(BaseRequest):
    """PTB transport that permits getMe only; message sends are mocked."""

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
        return 200, json.dumps(
            {
                "ok": True,
                "result": {
                    "id": 111,
                    "is_bot": True,
                    "first_name": "Offline",
                    "username": "offline_bot",
                },
            }
        ).encode()


class _Adapter(BasePlatformAdapter):
    async def connect(self, *, is_reconnect: bool = False) -> bool:
        return True

    async def disconnect(self):
        pass

    async def send(self, chat_id, content, reply_to=None, metadata=None) -> SendResult:
        return SendResult(success=True)

    async def get_chat_info(self, chat_id):
        return {}


def _source() -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        user_id="88",
        chat_id="42",
        user_name="fixture-user",
        chat_type="dm",
    )


def _event(text: str) -> MessageEvent:
    return MessageEvent(
        text=text,
        message_type=MessageType.TEXT,
        source=_source(),
        message_id="fixture-message",
    )


def _plugin_handler(manager: PluginManager, name: str):
    entry = manager._plugin_commands.get(name)
    return entry["handler"] if entry else None


def _plugin_manager(allowed_ids=(88,)) -> PluginManager:
    manager = PluginManager()
    context = PluginContext(
        manifest=PluginManifest(
            name="secure-env-ingress-probe",
            version="0.0.0",
            description="Phase 0 compatibility probe",
        ),
        manager=manager,
    )
    with patch("hermes_cli.plugins.load_config_readonly", return_value={
        "plugins": {"entries": {"secure-env-ingress-probe": {
            "settings": {"allowed_telegram_user_ids": list(allowed_ids)}
        }}}
    }):
        register(context)
    return manager


def _idle_runner():
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="offline")}
    )
    adapter = MagicMock()
    adapter.send = AsyncMock()
    adapter._pending_messages = {}
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._voice_mode = {}
    runner.hooks = SimpleNamespace(
        emit=AsyncMock(), emit_collect=AsyncMock(return_value=[]), loaded_hooks=False
    )
    entry = SessionEntry(
        session_key=build_session_key(_source()),
        session_id="fixture-session",
        created_at=datetime.now(),
        updated_at=datetime.now(),
        platform=Platform.TELEGRAM,
        chat_type="dm",
    )
    runner.session_store = MagicMock()
    runner.session_store.get_or_create_session.return_value = entry
    runner.session_store.load_transcript.return_value = []
    runner.session_store.has_any_sessions.return_value = True
    runner._running_agents = {}
    runner._pending_messages = {}
    runner._pending_approvals = {}
    runner._session_db = None
    runner._reasoning_config = None
    runner._provider_routing = {}
    runner._fallback_model = None
    runner._show_reasoning = False
    runner._is_user_authorized = lambda _source: True
    runner._set_session_env = lambda _context: None
    runner._should_send_voice_reply = lambda *_args, **_kwargs: False
    runner._send_voice_reply = AsyncMock()
    runner._capture_gateway_honcho_if_configured = lambda *args, **kwargs: None
    runner._emit_gateway_run_progress = AsyncMock()
    runner._run_agent = AsyncMock(side_effect=AssertionError("/senv reached the LLM boundary"))
    return runner


def _busy_runner(mode: str = "steer"):
    from gateway.run import GatewayRunner

    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner._busy_input_mode = mode
    runner._busy_text_mode = "queue" if mode == "queue" else "interrupt"
    runner._profile_adapters = {}
    runner.adapters = {}
    runner._sessions = {}
    runner._draining = False
    runner._restart_requested = False
    runner.session_store = None
    runner.hooks = MagicMock()
    runner.hooks.emit = AsyncMock()
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = True
    runner._is_user_authorized = lambda source: True
    runner._session_has_compression_in_flight = AsyncMock(return_value=False)
    adapter = _Adapter(
        PlatformConfig(enabled=True, token="offline"), Platform.TELEGRAM
    )
    runner.adapters[Platform.TELEGRAM] = adapter
    event = _event(f"/senv {FIXTURE_ARGUMENT}")
    key = runner._session_key_for_source(event.source)
    agent = MagicMock()
    agent._active_children = []
    agent.steer.return_value = True
    runner._running_agents[key] = agent
    return runner, adapter, agent, event, key


def _telegram_update(bot, text: str, user_id=88, chat_type="private", business=False) -> Update:
    command_len = len("/senv")
    return Update.de_json(
        {
            "update_id": 10,
            "message": {
                "message_id": 472,
                "date": 1800000000,
                "chat": {"id": 42, "type": chat_type},
                "from": {"id": user_id, "is_bot": False, "first_name": "Human"},
                **({"business_connection_id": "fixture-business"} if business else {}),
                "text": text,
                "entities": [
                    {
                        "type": "bot_command",
                        "offset": 0,
                        "length": command_len,
                    }
                ],
            },
        },
        bot,
    )


@asynccontextmanager
async def _connected_telegram(monkeypatch, manager):
    from plugins.platforms.telegram.adapter import TelegramAdapter

    adapter = TelegramAdapter(
        PlatformConfig(enabled=True, token="111:offline-test", extra={})
    )
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "88")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_URL", "")
    monkeypatch.setattr(
        adapter,
        "_build_ptb_requests",
        AsyncMock(return_value=(_NoNetwork(), _NoNetwork())),
    )
    monkeypatch.setattr(adapter, "_start_polling_mode", AsyncMock())
    monkeypatch.setattr(adapter, "_start_post_connect_housekeeping", lambda: None)
    monkeypatch.setattr(
        adapter, "_restart_task_attr", lambda name, coroutine: coroutine.close()
    )
    monkeypatch.setattr(adapter, "_set_status_indicator", AsyncMock())
    adapter._message_handler = AsyncMock(
        side_effect=AssertionError("native /senv fell through to Hermes runner")
    )
    with patch("hermes_cli.plugins.get_plugin_manager", return_value=manager):
        assert await adapter.connect()
    try:
        yield adapter, adapter._app
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("text", ["", "   ", "hello", "/senv-other KEY=fixture"])
def test_guard_ignores_non_senv_and_empty_events(text):
    assert pre_gateway_dispatch(event=SimpleNamespace(text=text)) is None


@pytest.mark.parametrize("text", ["/senv KEY=fixture", "/senv@offline_bot KEY=fixture"])
def test_guard_recognizes_assignment_without_echo(text):
    result = pre_gateway_dispatch(event=SimpleNamespace(text=text))
    assert result is not None
    assert result["action"] == "skip"
    assert "fixture" not in result["reason"]


def test_plugin_registers_supported_surfaces():
    manager = _plugin_manager()

    assert _plugin_handler(manager, "senv") is not None
    assert manager.get_platform_handler_factories("telegram")
    assert manager._hooks["pre_gateway_dispatch"]


def test_plugin_discovers_from_isolated_hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    destination = home / "plugins" / "secure-env-ingress-probe"
    destination.parent.mkdir(parents=True)
    shutil.copytree(PROJECT_ROOT / "secure_env_ingress_probe", destination)
    (home / "config.yaml").write_text(
        "plugins:\n  enabled: [secure-env-ingress-probe]\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))

    manager = PluginManager()
    manager.discover_and_load()

    assert _plugin_handler(manager, "senv") is not None
    assert manager.get_platform_handler_factories("telegram")
    assert manager._hooks["pre_gateway_dispatch"]


@pytest.mark.asyncio
async def test_idle_register_command_stops_before_agent_and_transcript(monkeypatch):
    manager = _plugin_manager()
    runner = _idle_runner()
    monkeypatch.setattr(
        "hermes_cli.plugins.get_plugin_command_handler",
        lambda name: _plugin_handler(manager, name),
    )

    result = await runner._handle_message(_event(f"/senv {FIXTURE_ARGUMENT}"))

    assert result == SAFE_REPLY
    assert FIXTURE_ARGUMENT not in result
    runner._run_agent.assert_not_called()
    runner.session_store.append_to_transcript.assert_not_called()


@pytest.mark.asyncio
async def test_pre_dispatch_guard_drops_assignment_before_runner(monkeypatch):
    manager = _plugin_manager()
    runner = _idle_runner()
    monkeypatch.setattr(
        "hermes_cli.lifecycle.ainvoke_hook", manager.ainvoke_hook
    )

    admitted = await runner._hm_admit_event(_event(f"/senv {FIXTURE_ASSIGNMENT}"))

    assert admitted is None
    runner._run_agent.assert_not_called()
    runner.session_store.append_to_transcript.assert_not_called()


@pytest.mark.asyncio
async def test_pre_dispatch_guard_drops_assignment_before_busy_steer(monkeypatch):
    manager = _plugin_manager()
    runner, adapter, agent, event, key = _busy_runner("steer")
    event.text = f"/senv {FIXTURE_ASSIGNMENT}"
    monkeypatch.setattr("hermes_cli.lifecycle.ainvoke_hook", manager.ainvoke_hook)
    monkeypatch.setenv("HERMES_TELEGRAM_FOLLOWUP_GRACE_SECONDS", "0")

    result = await runner._handle_message(event)

    assert result is None
    agent.steer.assert_not_called()
    agent.interrupt.assert_not_called()
    assert key not in adapter._pending_messages


@pytest.mark.parametrize("argument", [FIXTURE_ARGUMENT, FIXTURE_ASSIGNMENT])
@pytest.mark.parametrize("busy", [False, True])
@pytest.mark.asyncio
async def test_native_telegram_handler_precedes_adapter_busy_guard(monkeypatch, argument, busy):
    manager = _plugin_manager()
    replies = []

    async def _reply_text(_message_self, text, **kwargs):
        replies.append((text, kwargs))

    monkeypatch.setattr(telegram.Message, "reply_text", _reply_text)
    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        if busy:
            adapter._active_sessions[build_session_key(_source())] = asyncio.Event()
        await app.process_update(
            _telegram_update(app.bot, f"/senv {argument}")
        )

    assert len(replies) == 1
    text, kwargs = replies[0]
    assert text == SAFE_REPLY
    assert argument not in text
    assert kwargs["reply_markup"].to_dict() == build_telegram_markup(PROBE_URL).to_dict()
    adapter._message_handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_native_telegram_reply_failure_does_not_fall_through(monkeypatch):
    manager = _plugin_manager()

    async def _failed_reply(*_args, **_kwargs):
        raise RuntimeError("fixture delivery failure")

    monkeypatch.setattr(telegram.Message, "reply_text", _failed_reply)
    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        await app.process_update(
            _telegram_update(app.bot, f"/senv {FIXTURE_ASSIGNMENT}")
        )

    adapter._message_handler.assert_not_awaited()


@pytest.mark.parametrize("allowed_ids,user_id,chat_type,business", [
    ((), 88, "private", False),
    ((88,), 99, "private", False),
    ((88,), 88, "group", False),
    ((88,), 88, "private", True),
])
@pytest.mark.asyncio
async def test_native_telegram_denies_unapproved_context(
    monkeypatch, allowed_ids, user_id, chat_type, business
):
    manager = _plugin_manager(allowed_ids)
    reply = AsyncMock()
    monkeypatch.setattr(telegram.Message, "reply_text", reply)
    async with _connected_telegram(monkeypatch, manager) as (adapter, app):
        await app.process_update(_telegram_update(
            app.bot, f"/senv {FIXTURE_ASSIGNMENT}", user_id, chat_type, business
        ))
    reply.assert_not_awaited()
    adapter._message_handler.assert_not_awaited()


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="native handler factory failure leaves the ordinary Telegram command route active",
)
@pytest.mark.asyncio
async def test_native_factory_failure_must_reserve_command(monkeypatch):
    from plugins.platforms.telegram.adapter import TelegramAdapter

    manager = PluginManager()
    context = PluginContext(
        manifest=PluginManifest(name="broken-probe", version="0.0.0"),
        manager=manager,
    )

    def broken_factory(application, adapter):
        raise RuntimeError("fixture registration failure")

    context.register_platform_handler("telegram", broken_factory)
    core_route = AsyncMock()
    monkeypatch.setattr(TelegramAdapter, "_handle_command", core_route)
    async with _connected_telegram(monkeypatch, manager) as (_, app):
        await app.process_update(_telegram_update(app.bot, f"/senv {FIXTURE_ASSIGNMENT}"))
    core_route.assert_not_awaited()


def test_telegram_markup_serializes_separate_url_and_web_app_buttons():
    payload = build_telegram_markup(PROBE_URL).to_dict()

    assert payload == {
        "inline_keyboard": [
            [{"text": "Open as link", "url": PROBE_URL}],
            [
                {
                    "text": "Open as Mini App",
                    "web_app": {"url": PROBE_URL},
                }
            ],
        ]
    }


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Hermes runner busy dispatch resolves only core CommandDef entries; "
        "register_command('senv') is not consulted and the text is steered"
    ),
)
@pytest.mark.asyncio
async def test_expected_failure_register_command_is_fail_closed_if_event_reaches_busy_runner(monkeypatch):
    manager = _plugin_manager()
    runner, adapter, agent, event, key = _busy_runner("steer")
    called = []
    handler = _plugin_handler(manager, "senv")

    def _recording_handler(raw_args):
        called.append(raw_args)
        return handler(raw_args)

    monkeypatch.setattr(
        "hermes_cli.plugins.get_plugin_command_handler",
        lambda name: _recording_handler if name == "senv" else None,
    )
    monkeypatch.setattr("hermes_cli.lifecycle.ainvoke_hook", AsyncMock(return_value=[]))
    monkeypatch.setenv("HERMES_TELEGRAM_FOLLOWUP_GRACE_SECONDS", "0")

    await runner._handle_message(event)

    assert called == [FIXTURE_ARGUMENT]
    assert agent.steer.call_count == 0
    assert key not in adapter._pending_messages


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "pre_gateway_dispatch invocation errors are logged and converted to allow; "
        "the public hook has no mandatory/fail-closed mode"
    ),
)
@pytest.mark.asyncio
async def test_expected_failure_pre_dispatch_hook_error_must_drop_sensitive_command(monkeypatch):
    runner, adapter, agent, event, key = _busy_runner("steer")
    event.text = f"/senv {FIXTURE_ASSIGNMENT}"
    monkeypatch.setattr(
        "hermes_cli.lifecycle.ainvoke_hook",
        AsyncMock(side_effect=RuntimeError("fixture hook failure")),
    )
    monkeypatch.setenv("HERMES_TELEGRAM_FOLLOWUP_GRACE_SECONDS", "0")

    await runner._handle_message(event)

    agent.steer.assert_not_called()
    agent.interrupt.assert_not_called()
    assert key not in adapter._pending_messages
