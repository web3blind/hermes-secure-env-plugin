from __future__ import annotations

import asyncio
import copy
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from secure_env_ingress.command import CommandController
from secure_env_ingress.plugin import LazyRuntime, register


def _update(text: str, owner: int = 88):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=owner, is_bot=False),
        effective_chat=SimpleNamespace(type="private"),
        effective_message=SimpleNamespace(
            text=text, business_connection_id=None, reply_text=AsyncMock()
        ),
    )


class _SchemaRuntime:
    instances: list["_SchemaRuntime"] = []

    def __init__(self, settings, _home, _token):
        self.settings = copy.deepcopy(settings)
        self.calls: list[tuple] = []
        self.closed = False
        self.__class__.instances.append(self)

    def create(self, owner, name):
        keys = tuple(self.settings["profiles"][name]["keys"])
        self.calls.append(("create", owner, name, keys))
        return {"url": "https://example.invalid/" + ",".join(keys), "web_app_url": None}

    def cancel(self, owner):
        self.calls.append(("cancel", owner))

    def status(self):
        return "ready:" + self.settings["profiles"]["one"]["keys"][0]

    def close(self):
        self.closed = True


def _creator(runtime, state, entered=None, release=None):
    def create(owner, name, fields, reservation):
        def prepare():
            if entered is not None and fields == ("first",):
                entered.set()
                assert release.wait(3)
            state["profiles"][name] = {"keys": list(fields)}
            definition = SimpleNamespace(name=name, keys=fields, target="target")
            return definition, copy.deepcopy(state)

        return runtime.create_reserved(owner, name, reservation, prepare)

    return create


@pytest.mark.asyncio
async def test_concurrent_same_profile_acknowledgements_match_created_schemas(monkeypatch, tmp_path):
    _SchemaRuntime.instances.clear()
    monkeypatch.setattr("secure_env_ingress.runtime.IngressRuntime", _SchemaRuntime)
    state = {"allowed_telegram_user_ids": [88], "profiles": {}}
    runtime = LazyRuntime(copy.deepcopy(state), tmp_path, "token")
    entered, release = threading.Event(), threading.Event()
    controller = CommandController(
        runtime,
        frozenset({88}),
        form_creator=_creator(runtime, state, entered, release),
    )
    first = _update("/senv shared first")
    second = _update("/senv shared second")

    first_task = asyncio.create_task(controller.handle(first, None))
    assert await asyncio.to_thread(entered.wait, 3)
    second_task = asyncio.create_task(controller.handle(second, None))
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(first_task, second_task)

    first_text = first.effective_message.reply_text.call_args.args[0]
    second_text = second.effective_message.reply_text.call_args.args[0]
    first_url = first.effective_message.reply_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].url
    second_url = second.effective_message.reply_text.call_args.kwargs["reply_markup"].inline_keyboard[0][0].url
    assert "Fields: first." in first_text and first_url.endswith("/first")
    assert "Fields: second." in second_text and second_url.endswith("/second")


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", [99, 88])
async def test_status_snapshot_refresh_requires_authorization(monkeypatch, tmp_path, owner):
    monkeypatch.setattr("secure_env_ingress.runtime.IngressRuntime", _SchemaRuntime)
    initial = {"allowed_telegram_user_ids": [88], "profiles": {"one": {"keys": ["A"]}}}
    changed = {"allowed_telegram_user_ids": [88], "profiles": {"one": {"keys": ["B"]}}}
    raw_initial = {"plugins": {"entries": {"secure-env-ingress": {"settings": initial}}}}
    raw_changed = {"plugins": {"entries": {"secure-env-ingress": {"settings": changed}}}}
    snapshots = iter((raw_initial, raw_changed, raw_changed))

    class Context:
        plugin_id = "secure-env-ingress"
        def register_skill(self, *_args, **_kwargs): pass
        def register_command(self, *_args, **_kwargs): pass
        def register_hook(self, *_args, **_kwargs): pass
        def register_platform_handler(self, _platform, factory): self.factory = factory
        def on_unload(self, callback): self.close = callback

    class Application:
        bot = SimpleNamespace(token="token")
        def add_handler(self, handler): self.handler = handler
        def remove_handler(self, _handler): pass

    ctx, application = Context(), Application()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with patch("hermes_cli.plugins.load_config_readonly", side_effect=lambda: next(snapshots)):
        register(ctx)
        ctx.factory(application, object())
        controller = application.handler.callback.__self__
        active = SimpleNamespace(closed=False, close=lambda: setattr(active, "closed", True))
        controller.runtime._runtime = active
        update = _update("/senv status", owner=owner)
        await controller.handle(update, None)

    assert active.closed is (owner == 88)
    assert controller.runtime.settings == (changed if owner == 88 else initial)
    if owner == 88:
        assert update.effective_message.reply_text.call_args.args == ("ready:B",)
    else:
        update.effective_message.reply_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_cancel_waits_for_older_definition_and_prevents_late_create(monkeypatch, tmp_path):
    _SchemaRuntime.instances.clear()
    monkeypatch.setattr("secure_env_ingress.runtime.IngressRuntime", _SchemaRuntime)
    state = {"allowed_telegram_user_ids": [88], "profiles": {}}
    runtime = LazyRuntime(copy.deepcopy(state), tmp_path, "token")
    entered, release = threading.Event(), threading.Event()
    controller = CommandController(
        runtime,
        frozenset({88}),
        form_creator=_creator(runtime, state, entered, release),
    )
    create_task = asyncio.create_task(controller.handle(_update("/senv shared first"), None))
    assert await asyncio.to_thread(entered.wait, 3)
    cancel_task = asyncio.create_task(controller.handle(_update("/senv cancel"), None))
    await asyncio.sleep(0.05)
    assert not cancel_task.done()
    release.set()
    await asyncio.gather(create_task, cancel_task)
    calls_at_return = [call for instance in _SchemaRuntime.instances for call in instance.calls]
    await asyncio.sleep(0.05)
    assert [call for instance in _SchemaRuntime.instances for call in instance.calls] == calls_at_return
    assert not any(call[0] == "create" for call in calls_at_return)


@pytest.mark.asyncio
async def test_handler_cancellation_waits_for_definition_worker_then_cleans_up(monkeypatch, tmp_path):
    _SchemaRuntime.instances.clear()
    monkeypatch.setattr("secure_env_ingress.runtime.IngressRuntime", _SchemaRuntime)
    state = {"allowed_telegram_user_ids": [88], "profiles": {}}
    runtime = LazyRuntime(copy.deepcopy(state), tmp_path, "token")
    entered, release = threading.Event(), threading.Event()
    controller = CommandController(
        runtime,
        frozenset({88}),
        form_creator=_creator(runtime, state, entered, release),
    )
    task = asyncio.create_task(controller.handle(_update("/senv shared first"), None))
    assert await asyncio.to_thread(entered.wait, 3)
    task.cancel()
    await asyncio.sleep(0.05)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    calls_at_return = [call for instance in _SchemaRuntime.instances for call in instance.calls]
    await asyncio.sleep(0.05)
    assert [call for instance in _SchemaRuntime.instances for call in instance.calls] == calls_at_return
    assert calls_at_return[-1][:2] == ("cancel", 88)
