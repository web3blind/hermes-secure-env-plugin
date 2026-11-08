"""Registered tools → synthetic Telegram adapter → verified HTTPS → Chromium.

Only delivery/CA provisioning is synthetic; no browser/target/Vault guard mocks.
"""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_retained_login_browser import browser as browser, env as env
from test_retained_login_frameworks import mount
from test_runtime_e2e import post


@pytest.mark.parametrize('framework', ['vue', 'vuetify'])
def test_https_store_then_exact_dynamic_fill(env, monkeypatch, framework, caplog):
    from test_tool_https_e2e import running_gateway_loop
    from generic_helpers import registered
    from gateway import session_context as sc
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.run import GatewayRunner, _profile_runtime_scope
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from secure_env_ingress import runtime as runtime_module
    from tools.registry import registry

    mount(env, framework)
    root = Path(env.settings['cert_path']).parent / 'root.pem'
    original_runtime = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', lambda cfg, home, token: original_runtime(cfg, home, token, trust_roots=root))
    deliveries = []
    stages = []
    password = 'HTTPS-only-Synthetic-Dynamic-Password!'

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            stages.append(('delivery', chat_id, metadata))
            assert chat_id == '7' and metadata == {}
            assert 'login form' in content
            link = content.split('form: ', 1)[1].split(' for ', 1)[0]
            deliveries.append(link)
            token = urlsplit(link).fragment
            status, form = await asyncio.to_thread(post, env.settings, root, '/session', {'token': token, 'initData': ''})
            stages.append(('session', status, sorted(form.keys())))
            assert status == 200 and form['kind'] == 'browser_vault' and form['keys'] == ['Username', 'Password', 'Authenticator key (optional)']
            status, body = await asyncio.to_thread(post, env.settings, root, '/submit', {'token': token, 'initData': '', 'values': ['account@example.test', password]})
            assert (status, body) == (200, {'saved': True})
            return SimpleNamespace(success=True)

    gateway = object.__new__(GatewayRunner)
    gateway.adapters = {Platform.TELEGRAM: Adapter()}
    gateway._profile_adapters = {}
    gateway._primary_profile_name = 'default'
    gateway.config = SimpleNamespace()
    with running_gateway_loop() as loop, registered(monkeypatch, env.home, settings=env.settings), _profile_runtime_scope(env.home, {}):
        gateway._gateway_loop = loop
        invoke_hook('pre_gateway_dispatch', event=MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='7', chat_type='dm'), text='synthetic login'), gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='7', chat_type='dm', session_id=env.browser.sup.task_id, session_key='synthetic-https-dynamic', cron_session='')
        try:
            raw = registry.dispatch('secure_env_vault', {'origin': env.origin, 'label': 'Synthetic dynamic account', 'mode': 'login'}, task_id=env.browser.sup.task_id, session_id=env.browser.sup.task_id)
            saved = json.loads(raw)
            assert saved['status'] == 'saved', (saved, stages)
            assert len(deliveries) == 1 and deliveries[0] not in raw
            result = json.loads(registry.dispatch('secure_login_fill', {'handle': saved['handle'], 'parent': env.parent, 'origin': env.origin}, task_id=env.browser.sup.task_id, session_id=env.browser.sup.task_id))
            assert result['status'] == 'filled', result
        finally:
            sc.clear_session_vars(tokens)
    assert env.page.evaluate('(value)=>originalPassword===document.querySelector("#p")&&originalPassword.value===value', password)
    assert env.page.evaluate('window.passwordWrites===1')
    assert password not in raw and password not in str(result) and password not in caplog.text
    assert not (env.home / '.env').exists()
