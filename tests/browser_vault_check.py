"""Optional real CDP smoke: isolated HTTPS form -> encrypted Vault -> native fill.

Run with the Hermes interpreter and an already-running audited 127.0.0.1:18800 rail.
Never starts a browser, loads a user profile, or inspects unrelated tabs.
"""
import json
import os
from pathlib import Path
import tempfile
import urllib.request

from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
import secure_env_ingress

assert Path(secure_env_ingress.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1], 'Run with PYTHONPATH=.:tests to test checkout assets'


def main():
    from tools import browser_tool as bt
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from tools.browser_vault_tool import browser_vault_fill, browser_vault_list
    from secure_env_ingress.vault_ingress import capture_browser_target, assert_browser_target
    from agent.vault_store import VaultStore

    with urllib.request.urlopen('http://127.0.0.1:18800/json/version', timeout=3) as response:
        cdp_ws = json.load(response)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-vault-browser-') as directory:
        runtime, _, home, _ = make_runtime(Path(directory), mini=False)
        # This smoke explicitly exercises the supported legacy CDP backend.
        # Do not inherit host auto-selection of Browser Use in the disposable home.
        (home / 'config.yaml').write_text('browser:\n  backend: "off"\n')
        old_home = os.environ.get('HERMES_HOME')
        os.environ['HERMES_HOME'] = str(home)
        task = 'vault-ingress-disposable-test'
        supervisor = None
        prior_record = bt._active_sessions.get(task)
        prior_key = bt._last_active_session_key.get(task)
        assert prior_record is None and prior_key is None and SUPERVISOR_REGISTRY.get(task) is None
        try:
            # Start the existing HTTPS listener; no real account, browser profile, or auth session.
            runtime.create(7, 'service')
            origin = runtime._origin()
            with sync_playwright() as p:
                browser = p.chromium.connect_over_cdp('http://127.0.0.1:18800')
                context = browser.new_context(ignore_https_errors=True)
                login = context.new_page()
                try:
                    login.route('**/fixture-login', lambda route: route.fulfill(status=200, content_type='text/html',
                        body='<label for="username">Username</label><input id="username" autocomplete="username">'
                             '<label for="password">Password</label><input id="password" type="password" autocomplete="current-password">'))
                    login.goto(origin + '/fixture-login')
                    cdp_page = context.new_cdp_session(login)
                    target_id = cdp_page.send('Target.getTargetInfo')['targetInfo']['targetId']
                    cdp_page.detach()

                    class TargetedSupervisor(CDPSupervisor):
                        async def _attach_initial_page(self):
                            attach = await self._cdp('Target.attachToTarget', {'targetId': target_id, 'flatten': True})
                            self._page_session_id = sid = attach['result']['sessionId']
                            await self._enable_page_domains(sid, timeout=10.0)
                            await self._install_dialog_bridge(sid)

                    supervisor = TargetedSupervisor(task, cdp_ws)
                    supervisor.start()
                    with SUPERVISOR_REGISTRY._lock:
                        SUPERVISOR_REGISTRY._by_task[task] = supervisor
                    record = {'session_key': task, 'owner_task_id': task}
                    bt._active_sessions[task] = record
                    bt._last_active_session_key[task] = task
                    binding = capture_browser_target(origin, 'Synthetic login', task, task, 'test-session')
                    assert_browser_target(binding)
                    links = runtime.create_vault(('telegram', '7'), binding)
                    legacy = context.new_page()
                    try:
                        legacy.route('**/session', lambda route: route.fulfill(status=200, content_type='application/json',
                            body=json.dumps({'kind': 'browser_vault', 'label': 'Synthetic login', 'keys': ['Username', 'Password']})))
                        legacy.goto(links['url'])
                        old_user = legacy.get_by_label('Username', exact=True)
                        old_pass = legacy.get_by_label('Password', exact=True)
                        old_user.wait_for(state='visible')
                        assert legacy.locator('#fields input').count() == 2
                        assert legacy.evaluate('document.activeElement.id') == old_user.get_attribute('id')
                        legacy.keyboard.press('Tab')
                        assert old_pass.evaluate('(e) => e === document.activeElement')
                        legacy.keyboard.press('Tab')
                        assert legacy.get_by_role('button', name='Save').evaluate('(e) => e === document.activeElement')
                        legacy.keyboard.press('Shift+Tab')
                        assert old_pass.evaluate('(e) => e === document.activeElement')
                        print('LEGACY_TWO_FIELD_FOCUS=PASS')
                    finally:
                        legacy.close()
                    form = context.new_page()
                    errors = []
                    form.on('pageerror', lambda error: errors.append(type(error).__name__))
                    try:
                        response = form.goto(links['url'])
                        assert response.status == 200
                        username = form.get_by_label('Username', exact=True)
                        password = form.get_by_label('Password', exact=True)
                        authenticator = form.get_by_label('Authenticator key (optional)', exact=True)
                        username.wait_for(state='visible')
                        authenticator.wait_for(state='visible')
                        assert form.evaluate('location.hash') == ''
                        assert form.evaluate('document.activeElement.id') == username.get_attribute('id')
                        assert password.get_attribute('type') == 'password'
                        assert authenticator.get_attribute('type') == 'password'
                        assert not authenticator.get_attribute('required')
                        assert authenticator.get_attribute('aria-describedby') == 'secret-2-hint'
                        form.set_viewport_size({'width': 320, 'height': 720})
                        assert form.evaluate('document.documentElement.scrollWidth <= innerWidth')
                        controls = [username, password, authenticator, form.get_by_role('button', name='Save')]
                        assert all(control.get_attribute('tabindex') in (None, '0') for control in controls)
                        for control in controls[1:]:
                            form.keyboard.press('Tab')
                            assert control.evaluate('(e) => e === document.activeElement')
                        form.keyboard.press('Tab')
                        assert not controls[-1].evaluate('(e) => e === document.activeElement')
                        controls[-1].focus()
                        for control in reversed(controls[:-1]):
                            form.keyboard.press('Shift+Tab')
                            assert control.evaluate('(e) => e === document.activeElement')
                        form.keyboard.press('Shift+Tab')
                        assert not controls[0].evaluate('(e) => e === document.activeElement')
                        ax = context.new_cdp_session(form)
                        nodes = ax.send('Accessibility.getFullAXTree')['nodes']
                        ax.detach()
                        names = {node.get('name', {}).get('value') for node in nodes if node.get('role', {}).get('value') == 'textbox'}
                        assert {'Username', 'Password', 'Authenticator key (optional)'} <= names, names
                        optional_ax = next(node for node in nodes if node.get('name', {}).get('value') == 'Authenticator key (optional)' and node.get('role', {}).get('value') == 'textbox')
                        assert 'Optional. Paste the 2FA setup key' in optional_ax.get('description', {}).get('value', ''), optional_ax.get('description')
                        username.fill('fixture@example.test')
                        password.fill('disposable-fixture-password')
                        authenticator.fill('invalid!')
                        controls[-1].focus()
                        form.keyboard.press('Enter')
                        form.get_by_role('status').filter(has_text='authenticator key looks wrong').wait_for()
                        assert authenticator.get_attribute('aria-invalid') == 'true'
                        assert authenticator.get_attribute('aria-describedby') == 'secret-2-hint status'
                        assert authenticator.evaluate('(e) => e === document.activeElement')
                        assert not controls[-1].is_disabled()
                        authenticator.fill('')
                        assert authenticator.get_attribute('aria-invalid') is None
                        assert authenticator.get_attribute('aria-describedby') == 'secret-2-hint'
                        assert form.get_by_role('status').inner_text() == ''
                        controls[-1].focus()
                        form.keyboard.press('Enter')
                        form.get_by_role('status').filter(has_text='Login saved to the encrypted Vault').wait_for(timeout=10000)
                        assert all(control.input_value() == '' and control.is_disabled() for control in controls[:-1])
                        assert form.evaluate('document.activeElement.id') == 'status'
                        assert form.evaluate('localStorage.length + sessionStorage.length') == 0
                        assert errors == []
                    finally:
                        form.close()
                    store = VaultStore(home / 'vault')
                    meta = store.list_items()[0]
                    assert meta.origin == origin and meta.identifier == 'fixture@example.test'
                    assert b'disposable-fixture-password' not in (home / 'vault' / 'vault.json.enc').read_bytes()
                    listed = json.loads(browser_vault_list())
                    assert any(item['handle'] == meta.id for item in listed['items'])
                    assert 'disposable-fixture-password' not in json.dumps(listed)
                    login.get_by_label('Username').fill('fixture@example.test')
                    result = json.loads(browser_vault_fill(meta.id, task_id=task))
                    assert result.get('success'), {k: v for k, v in result.items() if k != 'result'}
                    assert login.get_by_label('Password').evaluate('(e) => e.value.length > 0')
                    assert 'disposable-fixture-password' not in json.dumps(result)
                    binding = capture_browser_target(origin, 'Synthetic login', task, task, 'test-session')
                    login.goto(origin.replace('127.0.0.1', 'localhost') + '/fixture-login')
                    try:
                        assert_browser_target(binding)
                    except ValueError as exc:
                        assert 'page changed' in str(exc)
                    else:
                        raise AssertionError('wrong HTTPS origin accepted')
                    login.goto(origin + '/fixture-login')
                    assert_browser_target(binding)
                    # Native fill may reattach to the SAME tab; capture its current session for replacement test.
                    binding = capture_browser_target(origin, 'Synthetic login', task, task, 'test-session')
                    replacement = context.new_page()
                    try:
                        replacement.goto(origin + '/fixture-login')
                        assert supervisor.focus_page(origin, accept='!!document.querySelector("input[type=password]")')['ok']
                        # If focus_page selected the old tab first, force a fresh attachment to the test page.
                        assert supervisor.focus_page(origin)['ok']
                        if supervisor._page_session_id == binding.page_session_id:
                            # Reattach explicitly to the original tab; a distinct CDP session must reject.
                            assert supervisor.focus_page(origin)['ok']
                        assert supervisor._page_session_id != binding.page_session_id
                        try:
                            assert_browser_target(binding)
                        except ValueError as exc:
                            assert 'page changed' in str(exc)
                        else:
                            raise AssertionError('replacement session accepted')
                    finally:
                        replacement.close()
                    print(json.dumps({'https_form': 'PASS', 'labels_focus_320px_status_cleared': 'PASS',
                                      'ciphertext': 'PASS', 'native_list': 'PASS',
                                      'native_fill_password_nonempty': True, 'wrong_origin_rejected': True,
                                      'replaced_session_rejected': True,
                                      'page_errors': len(errors)}))
                finally:
                    context.close()
                    browser.close()
        finally:
            if supervisor is not None:
                SUPERVISOR_REGISTRY.stop(task)
            bt._active_sessions.pop(task, None)
            bt._last_active_session_key.pop(task, None)
            runtime.close()
            if old_home is None:
                os.environ.pop('HERMES_HOME', None)
            else:
                os.environ['HERMES_HOME'] = old_home


if __name__ == '__main__':
    main()
