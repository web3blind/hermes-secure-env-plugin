"""Shipped HTTPS client execution in disposable Chromium; server stays real."""
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from test_runtime_e2e import make_runtime
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('multiline', [False, True])
def test_real_entry_client(nested, tmp_path, monkeypatch, multiline):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<textarea id=challenge></textarea>"')
    value = 'A\nБ🙂' if multiline else '!'
    s = spec(len(value), multiline=multiline)
    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=s)[0]
    context = nested.page.context.browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    try:
        links = runtime.create_vault(('telegram', '7'), t, mode='code')
        # Opening the protected UI backgrounds the destination. Restore only the
        # synthetic target when releasing this test's own outgoing request.
        def release_request(route):
            nested.page.bring_to_front()
            route.continue_()
        page.route('**/submit', release_request)
        page.goto(links['url'])
        editor = page.locator('#secret-0')
        editor.wait_for(state='visible')
        assert page.locator('input[type=checkbox]').is_checked() is False
        assert editor.evaluate('(e)=>e.tagName') == ('TEXTAREA' if multiline else 'INPUT')
        editor.fill(value)
        assert not page.locator('#secret-form').evaluate('(e)=>e.checkValidity()')
        page.keyboard.press('Tab')
        assert page.locator('input[type=checkbox]').evaluate('(e)=>document.activeElement===e')
        page.keyboard.press('Space')
        assert page.locator('input[type=checkbox]').is_checked()
        page.locator('#submit').click()
        page.wait_for_function('()=>document.querySelector("#status").textContent.startsWith("Code filled")', timeout=120000)
        assert editor.input_value() == '' and editor.is_disabled()
        assert links['completion'].result(timeout=5)['status'] == 'filled'
        assert leaf.evaluate('document.querySelector("#challenge").value') == value
        assert page.url.endswith('/e')
        assert not (home / 'vault').exists() and not (home / '.env').exists()
    finally:
        context.close()
        runtime.close()
        codes.release(t)


def test_legacy_assets_refuse_explicit_before_secret(nested, tmp_path, monkeypatch):
    from pathlib import Path
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    runtime, _, home, _ = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    context = nested.page.context.browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    submitted = []
    page.route('**/static/entry.js', lambda route: route.fulfill(status=200, content_type='application/javascript', body=Path(__file__).with_name('fixtures').joinpath('entry-legacy.js').read_text()))
    page.on('request', lambda request: submitted.append(True) if request.url.endswith('/submit') else None)
    try:
        links = runtime.create_vault(('telegram', '7'), t, mode='code')
        page.goto(links['url'])
        page.wait_for_function('()=>document.querySelector("#status").textContent.includes("invalid")')
        assert page.locator('#secret-form').is_hidden()
        assert page.locator('#secret-0').count() == 0 and not submitted
        assert leaf.evaluate('document.querySelector("#challenge").value') == ''
    finally:
        context.close()
        runtime.close()
        codes.release(t)
