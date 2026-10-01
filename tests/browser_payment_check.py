"""Real HTTPS card storage + native approved fill in a disposable CDP context.

Requires audited existing loopback rail. No real card, checkout, charge or profile.
Controlled synthetic Telegram callback resolves the REAL native consent entry.
Hosted cross-origin iframe controls are intentionally unsupported; never bypass them.
"""
import json
import os
from pathlib import Path
import tempfile
import urllib.request

from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
from test_payment_ingress import card_values
from payment_consent_helpers import payment_consent
import secure_env_ingress

assert Path(secure_env_ingress.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1], 'Use checkout PYTHONPATH'

TOKENS = ['cc-number', 'cc-name', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'postal-code']
CHECKOUT = ''.join(f'<label for="f{i}">{token}</label><input id="f{i}" autocomplete="{token}">' for i, token in enumerate(TOKENS))


def main():
    from agent.vault_store import VaultStore
    from tools import browser_tool as bt
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from tools.browser_vault_tool import browser_vault_fill, browser_vault_list
    from secure_env_ingress.vault_ingress import capture_login_target
    from secure_env_ingress.payment import PAYMENT_KEYS

    endpoint = os.environ.get('SENV_TEST_CDP', 'http://127.0.0.1:18800')
    with urllib.request.urlopen(endpoint + '/json/version', timeout=3) as response:
        cdp_ws = json.load(response)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-payment-browser-') as directory:
        runtime, _, home, _ = make_runtime(Path(directory), mini=False)
        (home / 'config.yaml').write_text('browser:\n  backend: "off"\n')
        old_home = os.environ.get('HERMES_HOME')
        os.environ['HERMES_HOME'] = str(home)
        task = 'payment-ingress-disposable-test'
        supervisor = None
        assert task not in bt._active_sessions and task not in bt._last_active_session_key and SUPERVISOR_REGISTRY.get(task) is None
        try:
            runtime.create(7, 'service')
            origin = runtime._origin()
            with payment_consent('deny') as storage_prompts:
                links = runtime.create_vault(('telegram', '7'),
                    capture_login_target(origin, 'Synthetic card', task, 'test-session'), mode='payment')
                print('STARTING_PLAYWRIGHT', flush=True)
                with sync_playwright() as p:
                    print('CONNECTING_CDP', flush=True)
                    browser = p.chromium.connect_over_cdp(endpoint, timeout=15000)
                    print('CDP_CONNECTED', flush=True)
                    context = browser.new_context(ignore_https_errors=True)
                    try:
                        errors = []
                        form = context.new_page()
                        form.on('pageerror', lambda error: errors.append(type(error).__name__))
                        print('OPENING_HTTPS_FORM', flush=True)
                        assert form.goto(links['url'], timeout=15000).status == 200
                        inputs = [form.get_by_label(key, exact=True) for key in PAYMENT_KEYS]
                        inputs[0].wait_for(state='visible')
                        assert form.evaluate('location.hash') == ''
                        assert form.evaluate('document.activeElement.id') == inputs[0].get_attribute('id')
                        assert inputs[0].get_attribute('type') == inputs[4].get_attribute('type') == 'password'
                        assert inputs[1].get_attribute('required') is None and inputs[5].get_attribute('required') is None
                        form.set_viewport_size({'width': 320, 'height': 720})
                        assert form.evaluate('document.documentElement.scrollWidth <= innerWidth')
                        controls = inputs + [form.get_by_role('button', name='Save')]
                        for control in controls[1:]:
                            form.keyboard.press('Tab')
                            assert control.evaluate('(e) => e === document.activeElement')
                        for control in reversed(controls[:-1]):
                            form.keyboard.press('Shift+Tab')
                            assert control.evaluate('(e) => e === document.activeElement')
                        ax = context.new_cdp_session(form)
                        nodes = ax.send('Accessibility.getFullAXTree')['nodes']
                        ax.detach()
                        names = {n.get('name', {}).get('value') for n in nodes if n.get('role', {}).get('value') == 'textbox'}
                        assert set(PAYMENT_KEYS) <= names
                        values = card_values()
                        for control, value in zip(inputs, values):
                            control.fill(value)
                        controls[-1].click()
                        form.get_by_role('status').filter(has_text='Card saved to the encrypted Vault').wait_for(timeout=10000)
                        print('HTTPS_CARD_SAVED=PASS', flush=True)
                        assert all(control.input_value() == '' and control.is_disabled() for control in inputs)
                        assert form.evaluate('document.activeElement.id') == 'status'
                        assert form.evaluate('localStorage.length + sessionStorage.length') == 0
                        assert storage_prompts == []
                        meta = VaultStore(home / 'vault').list_items()[0]
                        assert meta.kind == 'payment' and meta.origin == origin
                        assert values[0].encode() not in (home / 'vault' / 'vault.json.enc').read_bytes()
                        listed = browser_vault_list()
                        assert meta.id in listed and values[0] not in listed
                        form.close()
                        checkout = context.new_page()
                        checkout.route('**/fixture-checkout', lambda route: route.fulfill(status=200, content_type='text/html', body=CHECKOUT))
                        checkout.goto(origin + '/fixture-checkout')
                        page_session = context.new_cdp_session(checkout)
                        target_id = page_session.send('Target.getTargetInfo')['targetInfo']['targetId']
                        page_session.detach()

                        class TargetedSupervisor(CDPSupervisor):
                            async def _attach_initial_page(self):
                                attached = await self._cdp('Target.attachToTarget', {'targetId': target_id, 'flatten': True})
                                self._page_session_id = sid = attached['result']['sessionId']
                                await self._enable_page_domains(sid, timeout=10.0)
                                await self._install_dialog_bridge(sid)

                        supervisor = TargetedSupervisor(task, cdp_ws)
                        supervisor.start()
                        with SUPERVISOR_REGISTRY._lock:
                            SUPERVISOR_REGISTRY._by_task[task] = supervisor
                        bt._active_sessions[task] = {'session_key': task, 'owner_task_id': task}
                        bt._last_active_session_key[task] = task
                        for choice in ('deny', 'unresolved', 'missing'):
                            with payment_consent(choice, session='synthetic-fill-' + choice) as seen:
                                result = json.loads(browser_vault_fill(meta.id, task_id=task))
                            assert result['error_type'] == 'payment_declined'
                            assert checkout.locator('input').evaluate_all('(es) => es.every(e => !e.value)')
                            assert len(seen) == (0 if choice == 'missing' else 1)
                        with payment_consent('once', session='synthetic-fill-accept') as seen:
                            result = json.loads(browser_vault_fill(meta.id, task_id=task))
                        assert result.get('success') and len(seen) == 1
                        assert checkout.locator('input').evaluate_all('(es) => es.every(e => e.value.length > 0)')
                        assert values[0] not in json.dumps(result) and values[0] not in json.dumps(seen)
                        wrong = origin.replace('127.0.0.1', 'localhost')
                        checkout.goto(wrong + '/fixture-checkout')
                        with payment_consent('once', session='synthetic-wrong-origin'):
                            result = json.loads(browser_vault_fill(meta.id, task_id=task))
                        assert not result.get('success') and result.get('error_type') == 'origin_mismatch'
                        assert checkout.locator('input').evaluate_all('(es) => es.every(e => !e.value)')
                        # Hosted-payment controls in a foreign frame remain untouched.
                        checkout.route('**/iframe-checkout', lambda route: route.fulfill(status=200, content_type='text/html',
                            body=f'<iframe src="{wrong}/fixture-checkout"></iframe>'))
                        checkout.goto(origin + '/iframe-checkout')
                        frame = checkout.frame_locator('iframe')
                        frame.locator('input').first.wait_for()
                        with payment_consent('once', session='synthetic-iframe'):
                            result = json.loads(browser_vault_fill(meta.id, task_id=task))
                        assert not result.get('success')
                        assert frame.locator('input').evaluate_all('(es) => es.every(e => !e.value)')
                        assert errors == []
                        print(json.dumps({'https_payment_form': 'PASS', 'keyboard_ax_320px_clearing': 'PASS',
                            'native_encrypted_append_list': 'PASS', 'no_storage_consent': 'PASS',
                            'real_native_consent_accept_decline_unresolved_missing': 'PASS',
                            'native_payment_fill': 'PASS', 'wrong_origin_refused': 'PASS',
                            'cross_origin_iframe_unsupported_untouched': 'PASS', 'page_errors': 0}))
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
