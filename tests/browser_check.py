"""Optional real Chromium/CDP smoke; disposable loopback TLS and target only."""
import json
from pathlib import Path
import tempfile
from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime
import secure_env_ingress

assert Path(secure_env_ingress.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1], 'Run with PYTHONPATH=.:tests to test checkout assets'


def check(url, labels, *, before_submit=None, expected_status='Secrets saved'):
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp('http://127.0.0.1:18800')
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(type(error).__name__))
        try:
            response = page.goto(url)
            assert response.status == 200
            inputs = [page.get_by_label(label, exact=True) for label in labels]
            inputs[0].wait_for(state='visible')
            assert page.evaluate('location.hash') == ''
            assert page.evaluate('document.activeElement.id') == inputs[0].get_attribute('id')
            page.set_viewport_size({'width': 320, 'height': 720})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            controls = inputs + [page.get_by_role('button', name='Save')]
            assert all(control.get_attribute('tabindex') in (None, '0') for control in controls)
            for control in controls[1:]:
                page.keyboard.press('Tab')
                assert control.evaluate('(e) => e === document.activeElement'), f'Tab failed: {labels}'
            page.keyboard.press('Tab')
            assert not controls[-1].evaluate('(e) => e === document.activeElement'), 'Tab trapped on submit'
            controls[-1].focus()
            for control in reversed(controls[:-1]):
                page.keyboard.press('Shift+Tab')
                assert control.evaluate('(e) => e === document.activeElement'), f'Shift+Tab failed: {labels}'
            page.keyboard.press('Shift+Tab')
            assert not controls[0].evaluate('(e) => e === document.activeElement'), 'Shift+Tab trapped on first input'
            for label, control in zip(labels, inputs):
                assert control.get_attribute('type') == 'password'
                assert control.get_attribute('autocomplete') == 'off'
                assert control.evaluate('(e) => e.labels[0].textContent') == label
            ax = context.new_cdp_session(page)
            nodes = ax.send('Accessibility.getFullAXTree')['nodes']
            ax.detach()
            names = {node.get('name', {}).get('value') for node in nodes if node.get('role', {}).get('value') == 'textbox'}
            assert set(labels) <= names, names
            import os
            axe_path = os.environ.get('SENV_AXE_PATH')
            if axe_path:
                page.evaluate(Path(axe_path).read_text())
                violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => v.id)")
                print(json.dumps({'axe_violations': violations}))
                assert not violations
            for input in inputs:
                input.fill('browser-fixture-only')
            if before_submit:
                before_submit()
            controls[-1].focus()
            page.keyboard.press('Enter')
            page.get_by_role('status').filter(has_text=expected_status).wait_for()
            assert all(input.input_value() == '' and input.is_disabled() for input in inputs)
            assert page.get_by_role('status').get_attribute('tabindex') == '-1', f"HTML: {page.get_by_role('status').evaluate('(e) => e.outerHTML')}"
            page.wait_for_function("() => document.activeElement.id === 'status'", timeout=2000)
            assert page.evaluate('localStorage.length + sessionStorage.length') == 0
            assert errors == []
            print(json.dumps({'browser_flow': 'PASS', 'labels': labels, 'cleared_values': True, 'console_errors': len(errors)}))
        finally:
            context.close()
            browser.close()


if __name__ == '__main__':
    from urllib.parse import quote
    from test_runtime_e2e import signed_data
    for mini in (False, True):
        with tempfile.TemporaryDirectory(prefix='senv-browser-') as directory:
            runtime, config, home, _ = make_runtime(Path(directory))
            config['profiles']['service']['keys'] = ['SERVICE_TOKEN', 'SERVICE_SECRET']
            runtime.config = type(runtime.config).from_mapping(config)
            try:
                links = runtime.create(7, 'service')
                url = links['web_app_url' if mini else 'url']
                if mini:
                    url += '&tgWebAppData=' + quote(signed_data(), safe='')
                check(url, ['SERVICE_TOKEN', 'SERVICE_SECRET'])
                assert (home / '.env').exists()
                print('SYNTHETIC_MINI' if mini else 'NORMAL_BROWSER', 'WRITE_VERIFIED=True')
            finally:
                runtime.close()
    with tempfile.TemporaryDirectory(prefix='senv-browser-reject-') as directory:
        runtime, config, _, _ = make_runtime(Path(directory), mini=False)
        config['profiles']['service']['keys'] = ['SERVICE_TOKEN', 'SERVICE_SECRET']
        runtime.config = type(runtime.config).from_mapping(config)
        try:
            rejected = runtime.create(7, 'service')['url']
            with sync_playwright() as p:
                browser = p.chromium.connect_over_cdp('http://127.0.0.1:18800')
                context = browser.new_context(ignore_https_errors=True)
                try:
                    page = context.new_page()
                    page.goto(rejected.split('#')[0])
                    page.get_by_role('status').filter(has_text='invalid or has expired').wait_for()
                    assert page.evaluate('document.activeElement.id') == 'status'
                    assert page.locator('#secret-form').is_hidden()
                    assert page.evaluate('localStorage.length + sessionStorage.length') == 0
                    print('EXPIRED_LINK_FOCUS=PASS')
                finally:
                    context.close()
                    browser.close()
            check(rejected, ['SERVICE_TOKEN', 'SERVICE_SECRET'], before_submit=lambda: runtime.cancel(7),
                  expected_status='save result is unconfirmed')
        finally:
            runtime.close()
