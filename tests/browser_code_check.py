"""Optional real isolated CDP smoke for the HTTPS one-time-code ingress.

Run with the Hermes venv and an already-running audited 127.0.0.1:18800 relay.
Only owns a disposable context, target-specific CDP supervisor, and temp home.
Never uses existing tabs, accounts, or profile storage; never submits the site form.
"""
import json
import os
from pathlib import Path
import tempfile
import urllib.request

from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
import secure_env_ingress

assert Path(secure_env_ingress.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1], 'Use PYTHONPATH=.:tests:<Hermes checkout>'

CODE = 'A1B2C3'  # Synthetic fixture data only; never print or log this value.
TASK = 'code-ingress-disposable-test'


def fixture_page(kind):
    if kind == 'none':
        fields = '<label for="account">Account</label><input id="account" name="account">'
    elif kind == 'ambiguous':
        fields = ('<label for="first">Verification code</label><input id="first" name="verification_code" autocomplete="one-time-code">'
                  '<label for="second">Verification code</label><input id="second" name="verification_code" autocomplete="one-time-code">')
    else:
        fields = '<input id="otp" name="code" type="tel" aria-label="Введите код">'
    return ('<!doctype html><title>Disposable challenge</title><form id="challenge">' + fields +
            '<button type="submit">Sign in</button></form><script>'
            'window.siteSubmissions=0;document.getElementById("challenge").addEventListener("submit",'
            'e=>{window.siteSubmissions++;e.preventDefault()})</script>')


def main():
    from tools import browser_tool as bt
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from secure_env_ingress.vault_ingress import capture_browser_target

    with urllib.request.urlopen('http://127.0.0.1:18800/json/version', timeout=3) as response:
        cdp_ws = json.load(response)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-code-browser-') as directory:
        prior_home = os.environ.get('HERMES_HOME')
        supervisor = None
        assert bt._active_sessions.get(TASK) is None
        assert bt._last_active_session_key.get(TASK) is None
        assert SUPERVISOR_REGISTRY.get(TASK) is None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp('http://127.0.0.1:18800')
                context = browser.new_context(ignore_https_errors=True)
                try:
                    site = context.new_page()
                    site.route('**/fixture-code', lambda route: route.fulfill(status=200,
                        content_type='text/html', body=fixture_page('single')))
                    # The target remains our own tab; each case gets a fresh
                    # HTTPS listener/port because successful transfers shut down
                    # their listener and its old port can remain in TIME_WAIT.
                    cdp_page = context.new_cdp_session(site)
                    target_id = cdp_page.send('Target.getTargetInfo')['targetInfo']['targetId']
                    cdp_page.detach()

                    class TargetedSupervisor(CDPSupervisor):
                        async def _attach_initial_page(self):
                            attach = await self._cdp('Target.attachToTarget', {'targetId': target_id, 'flatten': True})
                            self._page_session_id = sid = attach['result']['sessionId']
                            await self._enable_page_domains(sid, timeout=10.0)
                            await self._install_dialog_bridge(sid)

                    supervisor = TargetedSupervisor(TASK, cdp_ws)
                    supervisor.start()
                    with SUPERVISOR_REGISTRY._lock:
                        SUPERVISOR_REGISTRY._by_task[TASK] = supervisor
                    record = {'session_key': TASK, 'owner_task_id': TASK}
                    bt._active_sessions[TASK] = record
                    bt._last_active_session_key[TASK] = TASK

                    def transfer(kind, navigate=False):
                        case_dir = Path(directory) / f'{kind}-{int(navigate)}'
                        case_dir.mkdir()
                        runtime, _, home, _ = make_runtime(case_dir, mini=False)
                        (home / 'config.yaml').write_text('browser:\n  backend: "off"\n')
                        os.environ['HERMES_HOME'] = str(home)
                        entry = None
                        try:
                            runtime.create(7, 'service')
                            origin = runtime._origin()
                            site.goto(origin + '/fixture-code')
                            if kind != 'single':
                                site.set_content(fixture_page(kind))
                            target = capture_browser_target(origin, 'Disposable challenge', TASK, TASK, 'fixture-session')
                            links = runtime.create_vault(('telegram', '7'), target, mode='code')
                            entry = context.new_page()
                            errors = []
                            submissions = []
                            entry.on('pageerror', lambda exc: errors.append(type(exc).__name__))
                            entry.on('response', lambda response: submissions.append((response.status, response.json()))
                                     if response.url.endswith('/submit') else None)
                            response = entry.goto(links['url'])
                            assert response.status == 200
                            field = entry.get_by_label('Verification code', exact=True)
                            field.wait_for(state='visible')
                            assert entry.locator('#fields input').count() == 1
                            assert field.get_attribute('type') == 'password'
                            assert field.get_attribute('autocomplete') == 'off'
                            assert field.get_attribute('required') is not None
                            assert entry.evaluate('document.activeElement.id') == field.get_attribute('id')
                            assert entry.evaluate('location.hash') == ''
                            entry.keyboard.press('Tab')
                            button = entry.get_by_role('button', name='Save')
                            assert button.evaluate('(e) => e === document.activeElement')
                            entry.keyboard.press('Shift+Tab')
                            assert field.evaluate('(e) => e === document.activeElement')
                            if navigate:
                                # Same target tab, different HTTPS host: target binding must reject.
                                site.goto(origin.replace('127.0.0.1', 'localhost') + '/fixture-code')
                            field.fill(CODE)
                            button.click()
                            entry.get_by_role('status').filter(has_text=(
                                'Code fill was not confirmed' if navigate or kind != 'single' else 'Code filled in the browser')).wait_for(timeout=10000)
                            assert field.input_value() == '' and field.is_disabled()
                            assert button.is_disabled()
                            assert entry.evaluate('document.activeElement.id') == 'status'
                            assert entry.evaluate('localStorage.length + sessionStorage.length') == 0
                            assert not errors, errors
                            outcome = links['completion'].result(timeout=3)
                            assert outcome['status'] == ('unknown' if navigate or kind != 'single' else 'filled'), outcome
                            assert len(submissions) == 1
                            if kind == 'single' and not navigate:
                                assert submissions[0] == (200, {'filled': True})
                            else:
                                assert submissions[0][0] == 409 and 'saved' not in submissions[0][1]
                            assert outcome.get('saved') is not True
                            assert site.evaluate('window.siteSubmissions === 0')
                            if kind == 'single' and not navigate:
                                assert site.locator('#otp').evaluate('(e, expected) => e.value === expected', CODE)
                            elif not navigate:
                                assert site.locator('input').evaluate_all('(xs) => xs.every(x => x.value === "")')
                            assert not (home / 'vault').exists() and not (home / '.env').exists()
                            assert not any(CODE in p.read_text(errors='ignore') for p in home.rglob('*') if p.is_file())
                            return outcome['status']
                        finally:
                            if entry is not None:
                                entry.close()
                            runtime.close()

                    assert transfer('single') == 'filled'
                    assert transfer('none') == 'unknown'
                    assert transfer('ambiguous') == 'unknown'
                    assert transfer('single', navigate=True) == 'unknown'
                    print(json.dumps({'https_entry_masked_focus_clear': 'PASS', 'native_cdp_fill': 'PASS',
                                      'filled_not_saved': 'PASS', 'no_site_submit': 'PASS',
                                      'no_vault_env_or_home_code': 'PASS', 'no_field_rejected': 'PASS',
                                      'ambiguous_rejected': 'PASS', 'navigation_rejected': 'PASS'}))
                finally:
                    context.close()
                    browser.close()
        finally:
            if supervisor is not None:
                SUPERVISOR_REGISTRY.stop(TASK)
            bt._active_sessions.pop(TASK, None)
            bt._last_active_session_key.pop(TASK, None)
            if prior_home is None:
                os.environ.pop('HERMES_HOME', None)
            else:
                os.environ['HERMES_HOME'] = prior_home


if __name__ == '__main__':
    main()
