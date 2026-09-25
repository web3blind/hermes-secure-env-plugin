"""Registered browser_vault -> Hermes dispatcher -> HTTPS -> native encrypted Vault."""
import asyncio
import json
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from generic_helpers import registered
from test_runtime_e2e import make_runtime, post


@contextmanager
def running_gateway_loop():
    """The gateway loop stays responsive while sync registry dispatch blocks."""
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def run():
        asyncio.set_event_loop(loop)
        loop.call_soon(ready.set)
        loop.run_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert ready.wait(3)
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(3)
        assert not thread.is_alive()
        loop.close()


def test_vault_tool_reports_bounded_browser_binding_failure(tmp_path, monkeypatch):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from hermes_cli.lifecycle import invoke_hook
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from tools.registry import registry

    sample, settings, home, _root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings['allowed_telegram_user_ids'] = [7]
    with registered(monkeypatch, home, settings=settings) as (manager, gateway):
        with _profile_runtime_scope(home, {}):
            event = MessageEvent(source=SessionSource(
                platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'),
                text='ordinary message')
            invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
                chat_type='group', session_id='sid', session_key='key', cron_session='')
            try:
                raw = registry.dispatch('browser_vault',
                    {'origin': 'https://site.test', 'label': 'Fixture'}, task_id='sid', session_id='sid')
            finally:
                sc.clear_session_vars(tokens)
    result = json.loads(raw)
    assert result['success'] is False
    assert result['reason'] == 'browser_binding'
    assert 'https://site.test' not in raw


def test_vault_tool_reports_bounded_session_binding_failure(tmp_path, monkeypatch):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry

    sample, settings, home, _root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    settings['allowed_telegram_user_ids'] = [7]
    with registered(monkeypatch, home, settings=settings):
        with _profile_runtime_scope(home, {}):
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
                chat_type='group', session_id='sid', session_key='key', cron_session='')
            try:
                raw = registry.dispatch('browser_vault',
                    {'origin': 'https://site.test', 'label': 'Fixture'}, task_id='wrong', session_id='sid')
            finally:
                sc.clear_session_vars(tokens)
    result = json.loads(raw)
    assert result['success'] is False
    assert result['reason'] == 'session_binding'
    assert 'https://site.test' not in raw


@pytest.mark.parametrize('mode', ['this_chat', 'home'])
@pytest.mark.parametrize('running_dispatch_loop', [False, True])
def test_registered_tool_https_native_vault(mode, running_dispatch_loop, tmp_path, monkeypatch):
    from agent.vault_store import VaultStore
    from gateway import config as gateway_config, session_context as sc
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.run import _profile_runtime_scope
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from secure_env_ingress import plugin, runtime as runtime_module
    from secure_env_ingress.vault_ingress import VaultTarget
    from tools.registry import registry

    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    settings.update(delivery=mode, ttl_seconds=600)
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.setattr(gateway_config, 'load_gateway_config', lambda: SimpleNamespace(
        get_home_channel=lambda platform: SimpleNamespace(chat_id='77', thread_id='55'),
        platforms={Platform.TELEGRAM: SimpleNamespace(enabled=True)}))

    original_runtime = runtime_module.IngressRuntime
    issued = []

    def disposable_runtime(cfg, active_home, token):
        runtime = original_runtime(cfg, active_home, token, trust_roots=root)
        original_create = runtime.create_vault

        def issue(owner, target):
            links = original_create(owner, target)
            claim = runtime._store.peek(urlsplit(links['url']).fragment)
            assert owner == ('telegram', '7')
            assert claim is not None and claim.expires_at - claim.created_at == 240
            assert 0 < links['expires_at'] - time.monotonic() <= 240
            issued.append(links['url'])
            return links

        runtime.create_vault = issue
        return runtime

    # CDP page binding is exercised separately; preserve real authorization,
    # registry bridge, gateway delivery, TLS, capability, and native Vault here.
    target = VaultTarget('https://site.test', 'Fixture', 'sid', 'sid', 123, 'sid', 'key')
    monkeypatch.setattr(plugin, 'capture_browser_target', lambda *args: target)
    monkeypatch.setattr(runtime_module, 'assert_browser_target', lambda _: None)
    monkeypatch.setattr('secure_env_ingress.vault_ingress.assert_browser_target', lambda _: None)
    observed = []

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            observed.append((chat_id, metadata, content))
            # Link is delivered only through this transport, never the tool result.
            url = content.split('One-time HTTPS login form: ', 1)[1].split(' for ', 1)[0]
            token = urlsplit(url).fragment
            status, body = await asyncio.to_thread(post, settings, root, '/submit', {
                'token': token, 'initData': '',
                'values': ['synthetic-user', 'synthetic-only-password']})
            assert (status, body) == (200, {'saved': True})
            return SimpleNamespace(success=True)

    from gateway.run import GatewayRunner
    gateway = object.__new__(GatewayRunner)
    gateway.adapters = {Platform.TELEGRAM: Adapter()}
    gateway._profile_adapters = {}
    gateway._primary_profile_name = 'default'
    gateway.config = gateway_config.GatewayConfig()
    with running_gateway_loop() as gateway_loop, registered(monkeypatch, home, settings=settings) as (manager, _):
        gateway._gateway_loop = gateway_loop
        monkeypatch.setattr(runtime_module, 'IngressRuntime', disposable_runtime)
        with _profile_runtime_scope(home, {}):
            event = MessageEvent(source=SessionSource(
                platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'),
                text='ordinary message')
            invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
            entry = registry.get_entry('browser_vault', scope=str(home))
            assert entry is not None and entry.is_async
            tokens = sc.set_session_vars(
                platform='telegram', user_id='7', chat_id='-600', chat_type='forum',
                thread_id='99', session_id='sid', session_key='key', profile='', cron_session='')
            try:
                def dispatch():
                    return registry.dispatch('browser_vault',
                        {'origin': target.origin, 'label': target.label},
                        task_id='sid', session_id='sid')

                async def inside_loop():
                    return dispatch()  # exercise Hermes' running-loop thread bridge

                raw = asyncio.run(inside_loop()) if running_dispatch_loop else dispatch()
            finally:
                sc.clear_session_vars(tokens)
        result = json.loads(raw)
        assert result['success'] is True and result['status'] == 'saved'
        assert result['saved'] is True and result['filled'] is False
        assert result['origin'] == target.origin
        assert len(issued) == 1 and len(observed) == 1
        assert observed[0][:2] == (
            ('-600', {'thread_id': '99'}) if mode == 'this_chat'
            else ('77', {'thread_id': '55'}))
        store = VaultStore(home / 'vault')
        meta = store.get_meta(result['handle'])
        assert meta is not None and meta.identifier == 'synthetic-user'
        assert meta.origin == target.origin and meta.kind == 'login'
        assert store.resolve_secret(meta.id) == {'password': 'synthetic-only-password'}
        from tools.browser_vault_tool import browser_vault_list
        native = json.loads(browser_vault_list())
        assert any(item['handle'] == meta.id and item['origin'] == target.origin
                   for item in native['items'])
        assert 'synthetic-only-password' not in json.dumps(native)
        assert issued[0] not in raw and 'synthetic-only-password' not in raw
        assert not (home / '.env').exists()
