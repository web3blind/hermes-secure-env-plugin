"""Real isolated Chromium + registered tool/HTTPS, unmodified supervisor API."""
import json
import asyncio
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import urllib.request

import pytest
from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
from generic_helpers import registered


def main():
    # Public candidate needs the isolated host's captured-CDP seam, not a
    # git-show replacement module whose registry has no capture API.
    from tools import browser_supervisor as module
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
                    second.set_content(markup + markup)
                    def target_id(page):
                        cdp = context.new_cdp_session(page)
                        try:
                            return cdp.send('Target.getTargetInfo')['targetInfo']['targetId']
                        finally:
                            cdp.detach()
                    parent = target_id(second)
                    second.bring_to_front()
                    scope = (str(home), task, 'key', '7', '-600', 'None')
                    picker = CodeSelection()
                    target, choices = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    assert target is None and choices['status'] == 'selection_required'
                    assert len(choices['candidates']) == 2
                    assert 'do-not-return-this' not in json.dumps(choices)
                    token = choices['candidates'][1]['selection']
                    with pytest.raises(ValueError):
                        picker.choose(('foreign',), origin, 'Fixture', task, token, parent=parent)
                    target, _ = picker.choose(scope, origin, 'Fixture', task, token, parent=parent)
                    assert_target(target)
                    with pytest.raises(ValueError):
                        picker.choose(scope, origin, 'Fixture', task, token, parent=parent)
                    # Discover again through the REAL registered plugin entry point.
                    sent, pending = [], []
                    class Adapter:
                        async def send(self, chat_id, content, metadata=None):
                            sent.append(True)
                            pending.append(asyncio.create_task(self.submit(content)))
                            return SimpleNamespace(success=True)
                        async def submit(self, content):
                            url = content.split(' form: ', 1)[1].split(' for ', 1)[0]
                            from playwright.async_api import async_playwright
                            async with async_playwright() as ap:
                                connection = await ap.chromium.connect_over_cdp(endpoint)
                                ui = await connection.new_context(ignore_https_errors=True)
                                try:
                                    entry = await ui.new_page()
                                    await entry.goto(url)
                                    field = entry.get_by_label('Verification code', exact=True)
                                    await field.fill('Q!7&z=R9')
                                    assert await field.evaluate('(e) => e.checkValidity()')
                                    await entry.get_by_role('button', name='Save').click()
                                    await entry.get_by_role('status').filter(has_text='Code filled in the browser').wait_for(timeout=10000)
                                finally:
                                    await ui.close()
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
                            missing = json.loads(registry.dispatch('secure_env_vault', {'origin': origin, 'label': 'Fixture', 'mode': 'code'}, task_id=task, session_id=task))
                            assert missing.get('error') and 'parent' in json.dumps(missing) and not sent
                            args = {'origin': origin, 'label': 'Fixture', 'mode': 'code', 'parent': parent}
                            choices = json.loads(registry.dispatch('secure_env_vault', args, task_id=task, session_id=task))
                            assert choices['status'] == 'selection_required' and not sent
                            cdp = context.new_cdp_session(second)
                            tid = cdp.send('Target.getTargetInfo')['targetInfo']['targetId']
                            cdp.detach()
                            assert tid == parent
                            assert len(choices['candidates']) == 2
                            assert all(c['page_ref'] == parent for c in choices['candidates'])
                            chosen = choices['candidates'][1]
                            result = json.loads(registry.dispatch('secure_env_vault', {**args, 'selection': chosen['selection']}, task_id=task, session_id=task))
                            assert result.get('status') == 'filled' and len(sent) == 1, result
                            async def drain():
                                await asyncio.gather(*pending)
                            asyncio.run_coroutine_threadsafe(drain(), gateway_loop).result(30)
                            assert 'Q!7&z=R9' not in json.dumps(result)
                        finally:
                            sc.clear_session_vars(tokens)
                    assert first.locator('input').input_value() == ''
                    assert second.locator('input').nth(0).input_value() == ''
                    assert second.locator('input').nth(1).input_value() == 'Q!7&z=R9'
                    second.close()
                    parent = target_id(first)
                    first.bring_to_front()
                    target, choices = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    assert target is not None and choices is None
                    first.goto(origin + '/login?state=different')
                    with pytest.raises(ValueError):
                        assert_target(target)
                    target, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    first.close()
                    with pytest.raises(Exception):
                        assert_target(target)
                    with pytest.raises(ValueError):
                        picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    form_page = context.new_page()
                    form_page.goto(origin + '/login')
                    parent = target_id(form_page)
                    form_page.bring_to_front()
                    form_page.set_content(markup + markup)
                    _, response = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    assert len(response['candidates']) == 2
                    assert len({c['page_ref'] for c in response['candidates']}) == 1
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, response['candidates'][1]['selection'], parent=parent)
                    from secure_env_ingress.code_targets import fill
                    assert fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').nth(0).input_value() == ''
                    assert form_page.locator('input').nth(1).input_value() == '654321'
                    form_page.goto(origin + '/login')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    form_page.evaluate("document.querySelector('input').outerHTML='<input autocomplete=one-time-code>'")
                    assert_target(selected)  # Context is still valid; missing selected stamp refuses the setter.
                    assert not fill(selected,'654321',time.monotonic()+10)
                    assert form_page.locator('input').input_value()==''
                    form_page.goto(origin + '/login')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    form_page.goto('about:blank')
                    with pytest.raises(ValueError):
                        assert_target(selected)
                    for mutation in (
                        "const e=document.querySelector('input'); e.replaceWith(e.cloneNode(true))",
                        "const f=document.createElement('form'); document.body.append(f); f.append(document.querySelector('input'))",
                        "document.querySelector('form').action='/other-challenge'",
                    ):
                        form_page.goto(origin + '/login')
                        selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                        form_page.evaluate('() => {' + mutation + '}')
                        assert_target(selected)
                        assert fill(selected,'654321',time.monotonic()+10)
                        assert form_page.locator('input').input_value()=='654321'
                    for mutation in (
                        "const f=document.createElement('form'); document.body.append(f); f.append(e)",
                        "e.form.action='/other-challenge'",
                    ):
                        form_page.goto(origin + '/login')
                        selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                        form_page.evaluate("() => {const e=document.querySelector('input'); e.addEventListener('focus', () => {" + mutation + "}, {once:true})}")
                        assert fill(selected, '654321', time.monotonic() + 10)
                        assert form_page.locator('input').input_value() == '654321'
                    form_page.goto(origin + '/login')
                    form_page.set_content('<form>' + '<input autocomplete="one-time-code" maxlength="1">' * 6 + '</form>')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    form_page.evaluate("() => {const all=document.querySelectorAll('input'); all[0].addEventListener('input', () => all[1].replaceWith(all[1].cloneNode(true)), {once:true})}")
                    assert fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').evaluate_all('(els)=>els.map(e=>e.value).join("")')=='654321'
                    form_page.goto(origin + '/login')
                    form_page.set_content('<form>' + '<input autocomplete="one-time-code" maxlength="1">' * 6 + '</form>')
                    selected, _ = picker.choose(scope, origin, 'Fixture', task, parent=parent)
                    assert fill(selected, '654321', time.monotonic() + 10)
                    assert form_page.locator('input').evaluate_all('(els) => els.map(e => e.value).join(\"\")') == '654321'
                    assert not (home / 'vault').exists()
                    print('STOCK_OWNER_FREE; EXACT_PARENT_SAME_PAGE_SELECTION; REGISTERED_HTTPS_FILL; NO_SECRET_OUTPUT; SINGLE_AUTO; NAVIGATION_AND_CLOSE_REFUSAL=PASS')
                finally:
                    picker.close()
                    context.close()
        finally:
            runtime.close()
            sup.stop()
            with module.SUPERVISOR_REGISTRY._lock:
                module.SUPERVISOR_REGISTRY._by_task.pop(task, None)


if __name__ == '__main__':
    main()
