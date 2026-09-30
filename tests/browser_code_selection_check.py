"""Real isolated Chromium + registered tool/HTTPS, unmodified supervisor API."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import urlsplit
import urllib.request

import pytest
from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime, post
from generic_helpers import registered


def main():
    # Load baseline core module, NOT today's uncommitted target_id patch.
    core = Path(os.environ['SENV_CORE_ROOT'])
    with tempfile.TemporaryDirectory(prefix='senv-baseline-') as baseline:
        path = Path(baseline) / 'browser_supervisor.py'
        path.write_bytes(subprocess.check_output(['git', '-C', str(core), 'show', 'HEAD:tools/browser_supervisor.py']))
        spec = importlib.util.spec_from_file_location('tools.browser_supervisor', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        import tools
        tools.browser_supervisor = module
        import inspect
        assert 'target_id' not in inspect.signature(module.CDPSupervisor.focus_page).parameters
        _run(module)


def _run(module):
    from secure_env_ingress.code_targets import CodeSelection, assert_target
    from secure_env_ingress import runtime as runtime_module
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry
    endpoint = os.environ['SENV_TEST_CDP_URL']
    with urllib.request.urlopen(endpoint + '/json/version', timeout=3) as r:
        ws = json.load(r)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-selection-') as directory, pytest.MonkeyPatch.context() as mp:
        runtime, settings, home, root = make_runtime(Path(directory), mini=False)
        mp.setenv('HERMES_HOME', str(home))
        (home / 'config.yaml').write_text('browser:\n  backend: "off"\n')
        task = 'selection-fixture'
        sup = module.CDPSupervisor(task, ws)
        sup.start()
        with module.SUPERVISOR_REGISTRY._lock:
            module.SUPERVISOR_REGISTRY._by_task[task] = sup
        try:
            # Fixture pages are intercepted; only the registered tool opens TLS.
            origin = runtime._origin()
            with sync_playwright() as p:
                browser = p.chromium.connect_over_cdp(endpoint)
                context = browser.new_context(ignore_https_errors=True)
                try:
                    markup = '<form><label>Verification code<input autocomplete="one-time-code" name="code"></label></form>'
                    context.route('**/login*', lambda route: route.fulfill(status=200, content_type='text/html', body=markup))
                    first = context.new_page()
                    first.goto(origin + '/login?state=do-not-return-this')
                    second = context.new_page()
                    second.goto(origin + '/login?state=do-not-return-this')
                    scope = (str(home), task, 'key', '7', '-600', 'None')
                    picker = CodeSelection()
                    target, choices = picker.choose(scope, origin, 'Fixture', task)
                    assert target is None and choices['status'] == 'selection_required'
                    assert len(choices['candidates']) == 2
                    assert 'do-not-return-this' not in json.dumps(choices)
                    token = choices['candidates'][1]['selection']
                    with pytest.raises(ValueError):
                        picker.choose(('foreign',), origin, 'Fixture', task, token)
                    target, _ = picker.choose(scope, origin, 'Fixture', task, token)
                    assert_target(target)
                    with pytest.raises(ValueError):
                        picker.choose(scope, origin, 'Fixture', task, token)
                    # Discover again through the REAL registered plugin entry point.
                    sent = []
                    class Adapter:
                        async def send(self, chat_id, content, metadata=None):
                            sent.append(content)
                            url = content.split(' form: ', 1)[1].split(' for ', 1)[0]
                            status, body = await asyncio.to_thread(post, settings, root, '/submit', {
                                'token': urlsplit(url).fragment, 'initData': '', 'values': ['123456']})
                            if status != 200:
                                print('FIXTURE_SUBMIT', status, body)
                            assert (status, body) == (200, {'filled': True})
                            return SimpleNamespace(success=True)
                    # Use the real TLS/runtime, only substitute its installation-specific cert fixture.
                    runtime.close()
                    factory = runtime_module.IngressRuntime
                    def test_runtime(cfg, h, token):
                        inst = factory(cfg, h, token, trust_roots=root)
                        original = inst.create_vault
                        def create(*args, **kwargs):
                            try:
                                return original(*args, **kwargs)
                            except Exception as exc:
                                print('FIXTURE_PREFLIGHT', type(exc).__name__, str(exc))
                                raise
                        inst.create_vault = create
                        return inst
                    mp.setattr(runtime_module, 'IngressRuntime', test_runtime)
                    from test_tool_https_e2e import running_gateway_loop
                    with running_gateway_loop() as gateway_loop, registered(mp, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
                        gateway._gateway_loop = gateway_loop
                        gateway.adapters = {Platform.TELEGRAM: Adapter()}
                        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'), text='fixture')
                        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
                        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', chat_type='group', session_id=task, session_key='key', cron_session='')
                        try:
                            args = {'origin': origin, 'label': 'Fixture', 'mode': 'code'}
                            choices = json.loads(registry.dispatch('browser_vault', args, task_id=task, session_id=task))
                            assert choices['status'] == 'selection_required' and not sent
                            cdp = context.new_cdp_session(second)
                            tid = cdp.send('Target.getTargetInfo')['targetInfo']['targetId']
                            cdp.detach()
                            chosen = next(c for c in choices['candidates'] if c['page_ref'] == tid)
                            result = json.loads(registry.dispatch('browser_vault', {**args, 'selection': chosen['selection']}, task_id=task, session_id=task))
                            assert result.get('status') == 'filled' and len(sent) == 1, result
                            assert '123456' not in json.dumps(result)
                        finally:
                            sc.clear_session_vars(tokens)
                    assert first.locator('input').input_value() == ''
                    assert second.locator('input').input_value() == '123456'
                    second.close()
                    target, choices = picker.choose(scope, origin, 'Fixture', task)
                    assert target is not None and choices is None
                    first.goto(origin + '/login?state=different')
                    with pytest.raises(ValueError):
                        assert_target(target)
                    target, _ = picker.choose(scope, origin, 'Fixture', task)
                    first.close()
                    with pytest.raises(Exception):
                        assert_target(target)
                    empty, response = picker.choose(scope, origin, 'Fixture', task)
                    assert empty is None and response['status'] == 'no_code_form'
                    form_page = context.new_page()
                    form_page.goto(origin + '/login')
                    form_page.set_content(markup + markup)
                    _, response = picker.choose(scope, origin, 'Fixture', task)
                    assert len(response['candidates']) == 2
                    assert len({c['page_ref'] for c in response['candidates']}) == 1
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, response['candidates'][1]['selection'])
                    from secure_env_ingress.code_targets import fill
                    assert fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').nth(0).input_value() == ''
                    assert form_page.locator('input').nth(1).input_value() == '654321'
                    form_page.goto(origin + '/login')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task)
                    form_page.evaluate("document.querySelector('input').outerHTML='<input autocomplete=one-time-code>'")
                    with pytest.raises(ValueError):
                        assert_target(selected)
                    form_page.goto(origin + '/login')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task)
                    form_page.goto('about:blank')
                    with pytest.raises(ValueError):
                        assert_target(selected)
                    for mutation in (
                        "const e=document.querySelector('input'); e.replaceWith(e.cloneNode(true))",
                        "const f=document.createElement('form'); document.body.append(f); f.append(document.querySelector('input'))",
                        "document.querySelector('form').action='/other-challenge'",
                    ):
                        form_page.goto(origin + '/login')
                        selected, _ = picker.choose(scope, origin, 'Fixture', task)
                        form_page.evaluate('() => {' + mutation + '}')
                        with pytest.raises(ValueError):
                            assert_target(selected)
                        assert not fill(selected, '654321', time.monotonic() + 10)
                        assert form_page.locator('input').input_value() == ''
                    for mutation in (
                        "const f=document.createElement('form'); document.body.append(f); f.append(e)",
                        "e.form.action='/other-challenge'",
                    ):
                        form_page.goto(origin + '/login')
                        selected, _ = picker.choose(scope, origin, 'Fixture', task)
                        form_page.evaluate("() => {const e=document.querySelector('input'); e.addEventListener('focus', () => {" + mutation + "}, {once:true})}")
                        assert not fill(selected, '654321', time.monotonic() + 10)
                        assert form_page.locator('input').input_value() == ''
                    form_page.goto(origin + '/login')
                    form_page.set_content('<form>' + '<input autocomplete="one-time-code" maxlength="1">' * 6 + '</form>')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task)
                    form_page.evaluate("() => {const all=document.querySelectorAll('input'); all[0].addEventListener('input', () => all[1].replaceWith(all[1].cloneNode(true)), {once:true})}")
                    assert not fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').nth(1).input_value() == ''
                    form_page.goto(origin + '/login')
                    form_page.set_content('<form>' + '<input autocomplete="one-time-code" maxlength="1">' * 6 + '</form>')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task)
                    assert fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').evaluate_all('(els) => els.map(e => e.value).join(\"\")') == '654321'
                    assert not (home / 'vault').exists()
                    print('BASELINE_CORE; MULTI_TAB_SELECTION; REGISTERED_HTTPS_FILL; NO_SECRET_OUTPUT; SINGLE_AUTO; NAVIGATION_AND_CLOSE_REFUSAL=PASS')
                finally:
                    context.close()
        finally:
            runtime.close()
            sup.stop()
            with module.SUPERVISOR_REGISTRY._lock:
                module.SUPERVISOR_REGISTRY._by_task.pop(task, None)


if __name__ == '__main__':
    main()
