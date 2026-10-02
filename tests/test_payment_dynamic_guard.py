"""Behavioral JS guard checks in disposable unauthenticated Chromium.

The registered-tool/native-consent integration is exercised separately by
browser_payment_iframe_check.py; these fast checks cover guard edge cases.
"""
import shutil

import pytest

from secure_env_ingress.payment_fill import _GUARD
from payment_fixture_helpers import HOST


@pytest.fixture(scope='module')
def chromium():
    playwright = pytest.importorskip('playwright.sync_api')
    executable = shutil.which('chromium')
    if not executable:
        pytest.skip('Chromium required for JS behavior checks')
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable, args=['--no-sandbox'])
        yield browser
        browser.close()


@pytest.fixture
def guard_page(chromium):
    context = chromium.new_context()
    page = context.new_page()
    page.set_content('''<form><label for="card">Card number</label>
        <input id="card" autocomplete="cc-number"><input id="cvc" autocomplete="cc-csc">
        <span id="brand" style="display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint"></span><input id="type" type="hidden"></form>''')
    yield page
    context.close()


def bind(page, inspection=False):
    page.evaluate('(inspection)=>{window.guard=(' + _GUARD + ')([document.querySelector("#card"),document.querySelector("#cvc")],inspection)}', inspection)
    assert page.evaluate('guard.valid()')


@pytest.mark.parametrize('formatting,accepted', [
    ('4242424242424242', True), ('4242 4242 4242 4242', True),
    ('42424242 42424242', True), ('4242-4242-4242-4242', False),
    ('4242\u00a0424242424242', False), ('４242424242424242', False),
    ('4242424242424243', False), ('4242424242424242x', False),
    (' 4242424242424242', False), ('4242424242424242 ', False),
    ('4242  424242424242', False), ('4242\t424242424242', False),
])
def test_number_normalization_is_ascii_space_only(guard_page, formatting, accepted):
    page = guard_page
    page.evaluate('(v)=>card.addEventListener("input",()=>card.value=v)', formatting)
    bind(page)
    assert page.evaluate('guard.focus(0)')
    result = page.evaluate('guard.write(0,"4242424242424242","cc-number")')
    assert result == dict(written=True, valid=accepted)


@pytest.mark.parametrize('inspection', [False, True])
def test_only_selected_guard_allows_decoration(guard_page, inspection):
    guard_page.evaluate(HOST)
    bind(guard_page, inspection)
    guard_page.evaluate('brand.style.display="block";document.querySelector("#type").setAttribute("value","visa")')
    assert guard_page.evaluate('guard.valid()') is (not inspection)


@pytest.mark.parametrize('css', [
    'form:has(#type[value="visa"]) {display:none}',
    '#brand[style] ~ input {visibility:hidden}',
    r'form:has(#type[v\61lue="visa"]) {display:none}',
    r'form:h\61s(#brand) {display:block}',
    '@media all {form:has(#type[value="visa"]) {display:none}}',
])
def test_attribute_sensitive_css_reverted_updates_reject(guard_page, css):
    guard_page.add_style_tag(content=css)
    bind(guard_page)
    guard_page.evaluate('let e=document.querySelector("#type");e.setAttribute("value","visa");e.removeAttribute("value")')
    assert guard_page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('mutation', [
    'card.disabled=true;card.disabled=false',
    'card.style.display="none";card.removeAttribute("style")',
    'document.querySelector("form").action="/evil";document.querySelector("form").removeAttribute("action")',
    'let p=card.parentNode,n=card.nextSibling;card.remove();p.insertBefore(card,n)',
    'document.body.className="evil";document.body.removeAttribute("class")',
    'document.querySelector("label").textContent="Another purpose"',
    'document.querySelector("label").style.color="red"',
    'card.setAttribute("aria-label","Other purpose")',
])
def test_protected_mutations_stay_invalid_after_revert(guard_page, mutation):
    bind(guard_page)
    guard_page.evaluate('()=>{const card=document.querySelector("#card");' + mutation + '}')
    assert guard_page.evaluate('guard.valid()') is False
    assert guard_page.evaluate('guard.focus(0)') is False


@pytest.mark.parametrize('event', ['focus', 'input', 'change'])
def test_later_callbacks_recheck_earlier_values(guard_page, event):
    page = guard_page
    page.evaluate('(event)=>cvc.addEventListener(event,()=>card.value="changed")', event)
    bind(page)
    assert page.evaluate('guard.focus(0)')
    assert page.evaluate('guard.write(0,"4242424242424242","cc-number").valid')
    focused = page.evaluate('guard.focus(1)')
    if event == 'focus':
        assert focused is False
    else:
        assert focused
        assert page.evaluate('guard.write(1,"123","cc-csc").valid') is False
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('adopted', [False, True])
def test_decoration_exception_supports_only_readable_safe_css(guard_page, adopted):
    page = guard_page
    if adopted:
        page.evaluate('()=>{const s=new CSSStyleSheet();s.replaceSync("form:has(#type[value]) {display:none}");document.adoptedStyleSheets=[s]}')
    else:
        page.route('https://css.test/style.css', lambda r: r.fulfill(body='input {color:black}', content_type='text/css', headers={'Access-Control-Allow-Origin': '*'}))
        page.add_style_tag(url='https://css.test/style.css')
    bind(page)
    page.evaluate('document.querySelector("#type").setAttribute("value","visa");document.querySelector("#type").removeAttribute("value")')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('placement', ['plain', 'nested', 'adopted', 'imported'])
@pytest.mark.parametrize('scope', [
    '(form:has(#type[value="visa"]))',
    '(body) to (#brand[style])',
    r'(form:h\61s(#type[v\61lue="visa"]))',
])
def test_scope_rules_refuse_reverted_decoration(guard_page, placement, scope):
    page = guard_page
    css = '@scope ' + scope + ' {input {opacity:0}}'
    if placement == 'nested':
        css = '@media all {' + css + '}'
    if placement == 'adopted':
        page.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    elif placement == 'imported':
        # Same-origin data sheet import keeps CSSOM readable.
        import urllib.parse
        page.add_style_tag(content='@import url("data:text/css,' + urllib.parse.quote(css, safe='') + '");')
        page.wait_for_function('document.styleSheets[0].cssRules[0].styleSheet !== null')
    else:
        page.add_style_tag(content=css)
    bind(page)
    page.evaluate('let e=document.querySelector("#type");e.setAttribute("value","visa");getComputedStyle(card).opacity;e.removeAttribute("value")')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('placement', ['plain', 'nested', 'adopted', 'imported'])
def test_container_rule_transient_opacity_change_refuses(guard_page, placement):
    page = guard_page
    page.evaluate("document.querySelector('form').style.containerType='inline-size'")
    css = '@container (max-width:200px) {input {opacity:0}}'
    if placement == 'nested':
        css = '@media all {' + css + '}'
    if placement == 'adopted':
        page.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    elif placement == 'imported':
        import urllib.parse
        page.add_style_tag(content='@import url("data:text/css,' + urllib.parse.quote(css, safe='') + '");')
        page.wait_for_function('document.styleSheets[0].cssRules[0].styleSheet !== null')
    else:
        page.add_style_tag(content=css)
    bind(page)
    page.evaluate('let e=document.querySelector("#type");e.setAttribute("value","visa");getComputedStyle(card).opacity;e.removeAttribute("value")')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('revert', [False, True])
@pytest.mark.parametrize('overlay', [
    'position:fixed;inset:0;z-index:99999;background:white',
    'position:absolute;left:0;top:0;width:100vw;height:100vh',
    'transform:scale(100);display:inline-block',
])
def test_unrelated_overlay_style_refuses(guard_page, overlay, revert):
    page = guard_page
    bind(page)
    page.evaluate('([css,revert])=>{const b=document.querySelector("#brand");const old=b.getAttribute("style");b.style.cssText=css;b.getBoundingClientRect();if(revert){if(old===null)b.removeAttribute("style");else b.setAttribute("style",old)}}', [overlay, revert])
    assert page.evaluate('guard.valid()') is False
    assert page.evaluate('guard.focus(1)') is False


def test_bounded_prebound_icon_display_is_allowed(guard_page):
    page = guard_page
    page.evaluate(HOST)
    bind(page)
    page.evaluate('brand.style.display="block"')
    assert page.evaluate('guard.valid()')
    page.evaluate('brand.style.display="none";brand.style.display="block"')
    assert page.evaluate('guard.valid()')


@pytest.mark.parametrize('setup', [
    'brand.style.width="65px"',
    'brand.style.padding="100px"',
    'brand.style.position="fixed"',
    'brand.style.pointerEvents="auto"',
    'brand.style.contain="none"',
    'brand.style.transform="scale(100)"',
    'brand.style.boxShadow="0 0 1000px 1000px black"',
    'brand.style.transitionDuration="1s"',
    'brand.tabIndex=0',
    'brand.textContent="not an empty icon"',
    'document.body.append(brand)',
])
def test_nonbounded_or_nonsibling_icons_never_get_exception(guard_page, setup):
    page = guard_page
    page.evaluate('()=>{' + setup + '}')
    bind(page)
    page.evaluate('brand.style.display="inline-block";brand.style.display="none"')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('mutation', [
    'brand.style.width="60px"',
    'brand.style.position="fixed"',
    'brand.style.zIndex="99999"',
    'brand.style.pointerEvents="auto"',
    'brand.style.transform="scale(100)"',
    'brand.style.setProperty("--unsafe","1")',
])
def test_prebound_icon_other_declarations_reverted_stay_invalid(guard_page, mutation):
    page = guard_page
    page.evaluate(HOST)
    bind(page)
    page.evaluate('()=>{const old=brand.getAttribute("style");' + mutation + ';brand.setAttribute("style",old)}')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('css', [
    '#brand {transform:scale(100)}',
    '#brand {zoom:100}',
    '#brand {animation:grow 1s infinite} @keyframes grow {to {transform:scale(100)}}',
    '#brand {transition:transform 1s}',
])
def test_hidden_icon_latent_css_effects_refuse_reverted_display(guard_page, css):
    page = guard_page
    page.add_style_tag(content=css)
    bind(page)
    page.evaluate('brand.style.display="inline-block";brand.getBoundingClientRect();brand.style.display="none"')
    assert page.evaluate('guard.valid()') is False


def test_nonnumber_fields_never_normalize(guard_page):
    page = guard_page
    page.evaluate('cvc.addEventListener("input",()=>cvc.value="1 2 3")')
    bind(page)
    assert page.evaluate('guard.focus(1)')
    assert page.evaluate('guard.write(1,"123","cc-csc").valid') is False
