"""Canonical routing and fail-closed tool authorization, without real credentials."""
import asyncio
import json
import time
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_env_ingress.delivery import Delivery
from secure_env_ingress.plugin import register


def test_home_destination_uses_profile_canonical_config_and_preserves_thread(tmp_path, monkeypatch):
    from gateway import config
    from hermes_constants import get_hermes_home
    home = tmp_path / 'profile'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    canonical = SimpleNamespace(chat_id='room-home', thread_id='topic-home')
    monkeypatch.setattr(config, 'load_gateway_config', lambda: SimpleNamespace(
        get_home_channel=lambda platform: canonical))
    assert Delivery('home', home).target('telegram', 'different', 'source-thread') == ('room-home', 'topic-home')
    assert Delivery('this_chat', home).target('telegram', 'source', 'source-thread') == ('source', 'source-thread')
    canonical.chat_id = ''
    with pytest.raises(ValueError):
        Delivery('home', home).target('telegram', 'source', 'source-thread')
    assert Path(get_hermes_home()) == home
    with pytest.raises(ValueError):
        Delivery('unexpected', home)


@pytest.mark.asyncio
async def test_home_send_uses_selected_profile_adapter_not_default(tmp_path, monkeypatch):
    from gateway import config
    from gateway.config import Platform
    home = tmp_path / 'named'
    home.mkdir()
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr('hermes_constants.profile_name_for_home', lambda h: 'named')
    canonical = SimpleNamespace(chat_id='canonical-room', thread_id='canonical-topic')
    loaded = SimpleNamespace(get_home_channel=lambda p: canonical,
                             platforms={Platform.TELEGRAM: SimpleNamespace(enabled=True)})
    monkeypatch.setattr(config, 'load_gateway_config', lambda: loaded)
    sent = []
    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            sent.append((chat_id, content, metadata))
            return SimpleNamespace(success=True)
    from gateway.run import GatewayRunner
    gateway = object.__new__(GatewayRunner)
    gateway.adapters = {Platform.TELEGRAM: object()}
    gateway._profile_adapters = {'named': {Platform.TELEGRAM: Adapter()}}
    gateway._primary_profile_name = 'default'
    await Delivery('home', home).send_gateway(gateway, 'telegram', 'origin-room', 'origin-topic', 'fixture URL')
    assert sent == [('canonical-room', 'fixture URL', {'thread_id': 'canonical-topic'})]
    async def failed_send(*args, **kwargs):
        return SimpleNamespace(success=False, error='private transport details')
    gateway._profile_adapters['named'][Platform.TELEGRAM].send = failed_send
    with pytest.raises(ValueError, match='delivery failed'):
        await Delivery('home', home).send_gateway(gateway, 'telegram', 'origin-room', 'origin-topic', 'fixture URL')


@pytest.mark.asyncio
async def test_tool_denies_unbound_context_without_issuing_form(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    class Context:
        plugin_id = 'secure-env-ingress'
        def __init__(self):
            self.tools = {}
        def register_tool(self, **kwargs):
            self.tools[kwargs['name']] = kwargs['handler']
        def register_skill(self, *args, **kwargs): pass
        def register_hook(self, *args, **kwargs): pass
        def register_command(self, *args, **kwargs): pass
        def on_unload(self, *args, **kwargs): pass
    ctx = Context()
    register(ctx)
    assert set(ctx.tools) == {'browser_vault'}
    result = json.loads(await ctx.tools['browser_vault'](
        {'origin': 'https://example.test', 'label': 'Synthetic'}, task_id='unbound'))
    assert result['success'] is False
    assert 'password' not in json.dumps(result).lower()


@pytest.mark.asyncio
async def test_tool_waits_for_saved_metadata_and_never_returns_bearer(tmp_path, monkeypatch):
    from gateway import session_context as sc
    from secure_env_ingress import plugin
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setattr(plugin, 'assert_profile_home', lambda h: None)
    monkeypatch.setattr('secure_env_ingress.vault_ingress.assert_browser_target', lambda target: None)
    monkeypatch.setattr(plugin, 'capture_browser_target',
        lambda origin, label, task, sid, key: SimpleNamespace(origin=origin, label=label))
    monkeypatch.setattr(plugin, 'configured_owners', lambda settings: frozenset({('telegram', '7')}))
    monkeypatch.setattr(plugin, 'Delivery', lambda mode, home: SimpleNamespace(
        target=lambda *a: ('-800', '99'), send_gateway=send))
    completed = Future()
    delivered = asyncio.Event()
    posted = []
    async def send(gateway, platform, chat, thread, text):
        posted.append((platform, chat, thread, text))
        delivered.set()
    class Context:
        plugin_id = 'secure-env-ingress'
        def __init__(self): self.tools, self.hook = {}, None
        def register_tool(self, **kwargs): self.tools[kwargs['name']] = kwargs['handler']
        def register_skill(self, *a, **kw): pass
        def register_hook(self, name, handler): self.hook = handler
        def register_command(self, *a, **kw): pass
        def on_unload(self, *a, **kw): pass
    ctx = Context()
    register(ctx)
    class Gateway:
        pass
    gateway = Gateway()
    ctx.hook(event=SimpleNamespace(internal=False, get_command=lambda: 'other'), gateway=gateway)
    class FakeRuntime:
        def refresh(self, settings): pass
        def create_vault(self, owner, target):
            assert owner == ('telegram', '7')
            return {'url': 'https://fixture.test/e#BEARER', 'completion': completed,
                    'expires_at': time.monotonic() + 120, 'group_id': 'group'}
        def cancel_group(self, group): completed.set_result({'status': 'cancelled'})
    monkeypatch.setattr(plugin.LazyRuntime, 'refresh', FakeRuntime.refresh)
    monkeypatch.setattr(plugin.LazyRuntime, 'create_vault', FakeRuntime.create_vault)
    monkeypatch.setattr(plugin.LazyRuntime, 'cancel_group', FakeRuntime.cancel_group)
    tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-800',
        chat_type='forum', thread_id='99', session_id='sid', session_key='key',
        profile='default', cron_session='')
    try:
        pending = asyncio.create_task(ctx.tools['browser_vault'](
            {'origin': 'https://fixture.test', 'label': 'Fixture'}, task_id='sid', session_id='sid'))
        await asyncio.wait_for(delivered.wait(), 3)
        assert not pending.done()
        completed.set_result({'status': 'saved', 'origin': 'https://fixture.test', 'handle': 'vault_fixture'})
        result = json.loads(await pending)
        assert result['success'] and result['saved'] and result['filled'] is False
        assert result['handle'] == 'vault_fixture' and 'BEARER' not in json.dumps(result)
        assert posted[0][1:3] == ('-800', '99')
    finally:
        sc.clear_session_vars(tokens)
