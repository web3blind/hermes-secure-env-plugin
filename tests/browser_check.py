"""Optional real Chromium/CDP smoke; disposable loopback TLS and target only."""
import json
from pathlib import Path
import tempfile
from playwright.sync_api import sync_playwright
from test_runtime_e2e import make_runtime


def check(url):
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp('http://127.0.0.1:18800')
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(type(error).__name__))
        try:
            response = page.goto(url)
            assert response.status == 200
            field = page.get_by_label('SERVICE_TOKEN', exact=True)
            field.wait_for(state='visible')
            assert page.evaluate('location.hash') == ''
            assert page.evaluate('document.activeElement.id') == field.get_attribute('id')
            assert field.get_attribute('type') == 'password'
            page.set_viewport_size({'width': 320, 'height': 720})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.keyboard.press('Tab')
            assert page.get_by_role('button', name='Save').evaluate('(e) => e === document.activeElement')
            page.keyboard.press('Shift+Tab')
            import os
            axe_path = os.environ.get('SENV_AXE_PATH')
            if axe_path:
                page.evaluate(Path(axe_path).read_text())
                violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}})).violations.map(v => v.id)")
                print(json.dumps({'axe_violations': violations}))
                assert not violations
            field.fill('browser-fixture-only')
            page.get_by_role('button', name='Save').click()
            page.get_by_role('status').filter(has_text='Secrets saved').wait_for()
            assert field.input_value() == ''
            assert field.is_disabled()
            assert page.evaluate('localStorage.length + sessionStorage.length') == 0
            assert errors == []
            print(json.dumps({'browser_flow': 'PASS', 'focus_and_labels': 'PASS', 'cleared_values': True, 'console_errors': len(errors)}))
        finally:
            context.close()
            browser.close()


if __name__ == '__main__':
    from urllib.parse import quote
    from test_runtime_e2e import signed_data
    for mini in (False, True):
        with tempfile.TemporaryDirectory(prefix='senv-browser-') as directory:
            runtime, _, home, _ = make_runtime(Path(directory))
            try:
                links = runtime.create(7, 'service')
                url = links['web_app_url' if mini else 'url']
                if mini:
                    url += '&tgWebAppData=' + quote(signed_data(), safe='')
                check(url)
                assert (home / '.env').exists()
                print('SYNTHETIC_MINI' if mini else 'NORMAL_BROWSER', 'WRITE_VERIFIED=True')
            finally:
                runtime.close()
