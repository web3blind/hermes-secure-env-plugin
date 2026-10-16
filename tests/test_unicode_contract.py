"""Frozen Unicode14 policy: real shipped Chromium UI and server capability guards."""
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit
import unicodedata

import pytest
from secure_env_ingress.exact_code import ValuePolicy, descriptor, validate_descriptor
from secure_env_ingress.server import _Handler
from secure_env_ingress.unicode_contract import public_contract, accepts_scalar
from test_exact_code_browser import spec as base_spec
from test_nested_code import nested as nested


def spec(n=1, layout='single', multiline=False):
    result = base_spec(n, layout, multiline)
    result['validation']['charset'] = 'unicode_text'
    return result


# Includes Unicode15/16 new symbols, old astral symbols, noncharacters, private
# use, formats, controls, lone surrogates and independent LF permission.
VECTORS = [
    ('!', False, True), ('Б', False, True), ('🙂', False, True),
    ('\U0001d11e', False, True), ('\U00010400', False, True),
    ('\U0001fae8', False, False), ('\U0001fae9', False, False),
    ('\U0001cc00', False, False), ('\U00031350', False, False),
    ('\u0378', False, False), ('\U0010ffff', False, False),
    ('\ue000', False, False), ('\U000f0000', False, False),
    ('\ud800', False, False), ('\udfff', False, False),
    ('\x00', False, False), ('\x7f', False, False), ('\x85', False, False),
    ('\t', False, False), ('\u200b', False, False), ('\u2028', False, False),
    ('\u2029', False, False), ('\r', True, False),
    ('\n', False, False), ('\n', True, True), ('A\n🙂', True, True),
]


def test_server_contract_is_frozen_not_host_ucd(monkeypatch):
    # A newer/older host UCD is deliberately unusable. Runtime never consults it.
    monkeypatch.setattr(unicodedata, 'category', lambda c: (_ for _ in ()).throw(AssertionError('host UCD used')))
    for value, multiline, allowed in VECTORS:
        assert ValuePolicy('unicode_text', len(value), multiline).accepts(value) is allowed
    assert not accepts_scalar(-1) and not accepts_scalar(0x110000)
    assert not accepts_scalar(True)
    for charset, value, allowed in [('ascii_digits', '012345', True), ('ascii_digits', '１２', False), ('ascii_printable_no_space', 'Ab!09', True), ('ascii_printable_no_space', 'A B', False)]:
        assert ValuePolicy(charset, len(value)).accepts(value) is allowed


def bad_contracts():
    original = public_contract()
    changed = deepcopy(original)
    changed['forbidden_ranges'].pop()
    boolean = deepcopy(original)
    boolean['forbidden_ranges'][0][0] = False
    return [None, {}, {'version': original['version']}, {**original, 'version': 'unicode-latest'},
            {**original, 'forbidden_ranges': []}, changed, boolean,
            {**original, 'extra': True}, {**original, 'forbidden_ranges': [[10, 0]]}]


@pytest.mark.parametrize('contract', bad_contracts())
def test_server_refuses_missing_or_malformed_policy(contract):
    d = descriptor(spec())
    d['unicode_contract'] = contract
    with pytest.raises(ValueError):
        validate_descriptor(d)
    with pytest.raises(ValueError):
        _Handler._validate_session_result({'label': 'Synthetic', 'kind': 'browser_code',
                                   'keys': ['Transient verification code'], 'target': d})


def test_missing_contract_and_mutation_are_closed():
    d = descriptor(spec())
    del d['unicode_contract']
    with pytest.raises(ValueError):
        validate_descriptor(d)
    a = public_contract()
    a['forbidden_ranges'].clear()
    assert not accepts_scalar(0x1fae8)
    assert public_contract()['forbidden_ranges']


def test_real_frontend_cross_version_and_policy_refusal(tmp_path):
    from playwright.sync_api import sync_playwright
    import secure_env_ingress
    script = Path(secure_env_ingress.__file__).parent.joinpath('static/entry.js').read_text()
    html = '''<p id="profile-label"></p><p id="intro"></p><p id="operation-summary"></p>
      <p id="status" tabindex="-1"></p><form id="secret-form" hidden><div id="fields"></div>
      <button id="submit" type="submit">Submit</button></form>'''
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path='/usr/bin/chromium', headless=True, args=['--no-sandbox'])
        context = browser.new_context()
        try:
            for value, multiline, allowed in VECTORS:
                d = descriptor(spec(len(value), multiline=multiline))
                page = _frontend(context, html, script, d)
                try:
                    page.locator('#secret-0').wait_for(state='visible')
                    if value == '\U0001fae8':
                        # This is an actual newer Chromium UCD, not a mocked
                        # regex. Its assigned symbol must still be refused.
                        assert page.evaluate(r"/\p{So}/u.test(String.fromCodePoint(0x1fae8))")
                    # Setting value directly is necessary for lone UTF16 surrogates
                    # and inputs whose native setter strips newline. It tests the
                    # actual shipped submit handler even when native validation
                    # would otherwise suppress submit before JS receives it.
                    page.evaluate('v => document.querySelector("#secret-0").value = String.fromCharCode(...v)', list(value.encode('utf-16-le', errors='surrogatepass')[i] + 256*value.encode('utf-16-le', errors='surrogatepass')[i+1] for i in range(0,len(value.encode('utf-16-le', errors='surrogatepass')),2)))
                    # Native setters normalize CR/LF before the handler sees them.
                    # For those vectors expose the raw synthetic value to the real
                    # handler as well; neither Unicode nor confirmation is mocked.
                    page.evaluate('units => {const e=document.querySelector("#secret-0");const raw=String.fromCharCode(...units);if(e.value!==raw) Object.defineProperty(e,"value",{configurable:true,get:()=>raw,set:()=>{}})}', list(int.from_bytes(value.encode('utf-16-le', errors='surrogatepass')[i:i+2], 'little') for i in range(0,len(value.encode('utf-16-le', errors='surrogatepass')),2)))
                    page.evaluate('document.querySelector("#secret-form").dispatchEvent(new Event("submit", {cancelable:true}))')
                    assert page.evaluate('submissions.length') == 0  # mandatory human confirmation
                    page.locator('input[type=checkbox]').check()
                    page.evaluate('document.querySelector("#secret-form").dispatchEvent(new Event("submit", {cancelable:true}))')
                    submitted = page.evaluate('submissions')
                    expected = allowed
                    assert bool(submitted) is expected, (ascii(value), browser.version)
                    assert ValuePolicy('unicode_text', len(value), multiline).accepts(value) is allowed
                    if submitted:
                        assert submitted[0]['confirmed'] is True
                    # Invalid input never calls /submit: one-time capability is
                    # retained locally for a correction, not spent on the backend.
                    if not expected:
                        assert page.evaluate('submissions.length') == 0
                finally:
                    page.close()
            for invalid in bad_contracts() + ['absent']:
                d = descriptor(spec())
                if invalid == 'absent':
                    del d['unicode_contract']
                else:
                    d['unicode_contract'] = invalid
                page = _frontend(context, html, script, d)
                try:
                    page.wait_for_function('()=>document.querySelector("#status").textContent.includes("invalid")')
                    assert page.locator('#secret-form').is_hidden()
                    assert page.locator('#secret-0').count() == 0
                    assert page.evaluate('submissions.length') == 0
                finally:
                    page.close()
        finally:
            context.close()
            browser.close()


def _frontend(context, html, script, target):
    import json
    page = context.new_page()
    session = {'label': 'Synthetic', 'kind': 'browser_code',
               'keys': ['Transient verification code'], 'target': target}
    def route(r):
        path = urlsplit(r.request.url).path
        if path == '/e':
            r.fulfill(status=200, content_type='text/html', body=html)
        elif path == '/session':
            r.fulfill(status=200, content_type='application/json', body=json.dumps(session))
        elif path == '/submit':
            r.fulfill(status=200, content_type='application/json', body='{"filled":true}')
        else:
            r.abort()
    page.route('**/*', route)
    page.add_init_script('window.submissions=[]; const oldFetch=window.fetch; window.fetch=(url,opts)=>{if(url==="/submit") submissions.push(JSON.parse(opts.body)); return oldFetch(url,opts)}')
    page.goto('https://unicode.test/e#synthetic-only')
    page.add_script_tag(content=script)
    return page


@pytest.mark.parametrize('value,confirmed', [('🙂', None), ('🙂', False), ('🙂', 'true'), ('🙂', True), ('\U0001fae8', True), ('\ud800', True)])
def test_real_https_confirmation_capability_guards(nested, tmp_path, monkeypatch, value, confirmed):
    from test_nested_code import setup_chain
    from test_runtime_e2e import make_runtime, post
    from secure_env_ingress import code_targets as codes
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    runtime, settings, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    try:
        links = runtime.create_vault(('telegram', '7'), target, mode='code')
        token = urlsplit(links['url']).fragment
        status, session = post(settings, root, '/session', {'token': token, 'initData': ''})
        assert status == 200
        validate_descriptor(session['target'])
        payload = {'token': token, 'initData': '', 'values': [value]}
        if confirmed is not None:
            payload['confirmed'] = confirmed
        status, _ = post(settings, root, '/submit', payload, timeout=120)
        success = value == '🙂' and confirmed is True
        assert status == (200 if success else 400)
        assert links['completion'].result(3)['status'] == ('filled' if success else 'rejected')
        assert leaf.evaluate('document.querySelector("#challenge").value') == (value if success else '')
        # Success may retire the HTTPS listener immediately. Replay authority is
        # asserted directly, not by racing the intentional socket shutdown.
        from secure_env_ingress.server import HTTPError
        with pytest.raises(HTTPError) as replay:
            runtime.submit(token, '', [value], confirmed=confirmed)
        assert replay.value.status == 410
        with pytest.raises(HTTPError) as replay:
            runtime.session(token, '')
        assert replay.value.status == 410
        assert not (home/'vault').exists() and not (home/'.env').exists()
    finally:
        runtime.close()
        codes.release(target)


def test_invalid_frontend_preserves_real_capability(nested, tmp_path, monkeypatch):
    from test_nested_code import setup_chain
    from test_runtime_e2e import make_runtime
    from secure_env_ingress import code_targets as codes
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    runtime, settings, home, root = make_runtime(tmp_path, mini=False)
    monkeypatch.setenv('HERMES_HOME', str(home))
    target = codes.discover(origin, 'Synthetic Unicode', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    context = nested.page.context.browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    submissions = []
    def release(route):
        submissions.append(True)
        nested.page.bring_to_front()
        route.continue_()
    page.route('**/submit', release)
    try:
        links = runtime.create_vault(('telegram', '7'), target, mode='code')
        token = urlsplit(links['url']).fragment
        page.goto(links['url'])
        editor = page.locator('#secret-0')
        editor.wait_for(state='visible')
        editor.fill('\U0001fae8')
        page.locator('input[type=checkbox]').check()
        page.locator('#submit').click()
        assert 'declared exact length and format' in page.locator('#status').inner_text()
        assert not submissions and not links['completion'].done()
        assert runtime.session(token, '')['target']['unicode_contract'] == public_contract()
        assert leaf.evaluate('document.querySelector("#challenge").value') == ''
        # The SAME capability remains usable for an assigned Unicode14 astral scalar.
        # Chromium154/Playwright replacement of a full maxlength=2 password
        # containing one astral scalar inserts nothing. Clear it first, as a
        # user can, rather than mistaking that native fixture behavior for R1.
        editor.fill('')
        editor.fill('\U0001f642')
        assert editor.input_value() == '\U0001f642'
        assert page.locator('#secret-form').evaluate('(e)=>e.checkValidity()'), page.locator('#secret-form').evaluate('(f)=>JSON.stringify(Array.from(f.elements).filter(e=>e.validity && !e.validity.valid).map(e=>({type:e.type,checked:e.checked,length:e.value?.length,min:e.minLength,max:e.maxLength,message:e.validationMessage})))')
        page.locator('#submit').click()
        page.wait_for_function('()=>/Code filled|Code fill was/.test(document.querySelector("#status").textContent)', timeout=120000)
        assert page.locator('#status').inner_text().startswith('Code filled'), {
            'completion_done': links['completion'].done(),
            'completion': links['completion'].result(1) if links['completion'].done() else None,
            'requests': len(submissions),
        }
        assert len(submissions) == 1
        assert links['completion'].result(3)['status'] == 'filled'
        assert leaf.evaluate('document.querySelector("#challenge").value') == '\U0001f642'
        assert editor.input_value() == '' and editor.is_disabled()
    finally:
        context.close()
        runtime.close()
        codes.release(target)
