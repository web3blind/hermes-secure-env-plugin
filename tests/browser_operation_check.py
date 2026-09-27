"""Optional real Chromium/CDP smoke for the generic secure_operation HTTPS form.

Run with the Hermes venv and an already-running audited 127.0.0.1:18800 rail.
Creates only an isolated browser context, synthetic trusted consumer, and temp home;
never touches existing tabs, user profiles, credentials, or production listeners.
Browser checks are not NVDA/screen-reader acceptance.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
import secure_env_ingress
from secure_env_ingress.operations import BoundOperation, bind, clear_consumers, register_consumer
from secure_env_ingress.runtime import OperationTarget

assert Path(secure_env_ingress.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1], (
    'Use PYTHONPATH=.:tests:<Hermes checkout> to test checkout assets')

SECRET = 'synthetic-operation-passphrase'  # Test fixture only; never print this value.
SUMMARY = 'Unlock synthetic fixture and record its action digest, target fixture'


def main():
    with urllib.request.urlopen('http://127.0.0.1:18800/json/version', timeout=3) as response:
        assert json.load(response)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-operation-browser-') as directory:
        runtime, _, home, _ = make_runtime(Path(directory), mini=False)
        previous_home = os.environ.get('HERMES_HOME')
        os.environ['HERMES_HOME'] = str(home)
        actions = []
        try:
            # Only trusted, locally installed test code constructs this operation.
            key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
                'sha256', SECRET.encode(), b'fixture-salt', 1000, dklen=32))
            ciphertext = Fernet(key).encrypt(b'synthetic-payload')

            def factory(raw):
                parameters = json.loads(raw)
                if parameters != {'target': 'fixture'}:
                    raise ValueError('invalid fixture target')
                frozen = bytes(ciphertext)

                def execute(secret):
                    candidate = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
                        'sha256', secret.encode(), b'fixture-salt', 1000, dklen=32))
                    plaintext = Fernet(candidate).decrypt(frozen)
                    actions.append(hashlib.sha256(plaintext + b':acted').hexdigest())
                    return secret  # Runtime must discard trusted consumer return values.

                return BoundOperation(SUMMARY, execute)

            register_consumer(home, 'fixture_action', factory)
            bound, canonical = bind(home, 'fixture_action', {'target': 'fixture'})
            identity = (int.from_bytes(hashlib.sha256(b'fixture_action' + canonical).digest(), 'big'), 0)
            target = OperationTarget('fixture_action', bound.summary, bound.execute,
                                     identity, 'fixture-session', '-600', '99')
            links = runtime.create_operation(('telegram', '7'), target)
            token = urlsplit(links['url']).fragment
            errors = []
            submissions = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp('http://127.0.0.1:18800')
                context = browser.new_context(ignore_https_errors=True)
                try:
                    page = context.new_page()
                    page.on('pageerror', lambda error: errors.append(type(error).__name__))
                    page.on('response', lambda response: submissions.append((response.status, response.json()))
                            if response.url.endswith('/submit') else None)
                    response = page.goto(links['url'])
                    assert response.status == 200
                    field = page.get_by_label('Secret', exact=True)
                    field.wait_for(state='visible')
                    button = page.get_by_role('button', name='Run operation')
                    summary = page.locator('#operation-summary')
                    assert summary.is_visible() and summary.inner_text() == SUMMARY
                    assert 'authorize this exact action' in page.locator('#intro').inner_text()
                    assert page.locator('#profile-label').inner_text() == 'fixture_action'
                    assert page.locator('#fields input').count() == 1
                    assert field.get_attribute('type') == 'password'
                    assert field.get_attribute('autocomplete') == 'off'
                    assert page.locator('#secret-form').get_attribute('autocomplete') == 'off'
                    assert field.get_attribute('required') is not None
                    assert page.evaluate('location.hash') == ''
                    assert field.evaluate('(e) => e === document.activeElement')
                    page.keyboard.press('Tab')
                    assert button.evaluate('(e) => e === document.activeElement')
                    page.keyboard.press('Shift+Tab')
                    assert field.evaluate('(e) => e === document.activeElement')
                    assert page.evaluate('localStorage.length + sessionStorage.length') == 0
                    field.fill(SECRET)
                    button.click()
                    page.get_by_role('status').filter(has_text='Operation reported complete').wait_for(timeout=10000)
                    assert submissions == [(200, {'completed': True})], submissions
                    assert links['completion'].result(timeout=3) == {'status': 'completed'}
                    assert actions == [hashlib.sha256(b'synthetic-payload:acted').hexdigest()]
                    assert field.input_value() == '' and field.is_disabled() and button.is_disabled()
                    assert page.evaluate('document.activeElement.id') == 'status'
                    assert page.evaluate('localStorage.length + sessionStorage.length') == 0
                    assert not errors, errors
                    assert SECRET not in page.content() and SECRET not in json.dumps(submissions)
                    assert SECRET not in json.dumps(links['completion'].result())
                    # A replay cannot run the synthetic action a second time.
                    from secure_env_ingress.server import HTTPError
                    try:
                        runtime.submit(token, '', [SECRET])
                    except HTTPError as exc:
                        assert exc.status == 410, exc.status
                    else:
                        raise AssertionError('operation capability replay accepted')
                    assert len(actions) == 1
                    assert not (home / '.env').exists() and not (home / 'vault').exists()
                    assert not any(SECRET in path.read_text(errors='ignore') for path in home.rglob('*') if path.is_file())
                finally:
                    context.close()
                    browser.close()
            print(json.dumps({'https_form_summary_mask_tab_status': 'PASS',
                              'trusted_action_exactly_once': 'PASS', 'no_secret_echo_or_persistence': 'PASS',
                              'page_errors': len(errors)}))
        finally:
            runtime.close()
            clear_consumers(home)
            if previous_home is None:
                os.environ.pop('HERMES_HOME', None)
            else:
                os.environ['HERMES_HOME'] = previous_home


if __name__ == '__main__':
    main()
