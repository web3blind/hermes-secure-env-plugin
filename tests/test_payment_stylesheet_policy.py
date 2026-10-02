"""Unmasked CSS-policy checks: only otherwise-allowed hidden value changes.

Test-only predicate mutation proves each refusal needs the scanner, not an icon,
geometry or protected-attribute rejection. Production guard is never weakened.
"""
import urllib.parse

import pytest

from secure_env_ingress.payment_fill import _GUARD
pytest_plugins = ['test_payment_dynamic_guard']


def sheet(page, css, placement):
    if placement == 'nested':
        css = '@media all {' + css + '}'
    if placement == 'adopted':
        page.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    elif placement == 'imported':
        page.add_style_tag(content='@import url("data:text/css,' + urllib.parse.quote(css, safe='') + '");')
        page.wait_for_function('Array.from(document.styleSheets).some(s=>s.cssRules[0]?.styleSheet)')
    elif placement == 'opaque':
        page.route('https://css.test/opaque.css', lambda r: r.fulfill(body=css, content_type='text/css'))
        page.add_style_tag(url='https://css.test/opaque.css')
    else:
        page.add_style_tag(content=css)


def verdict(page, guard):
    page.evaluate('if(window.guard)guard.close();window.guard=(' + guard + ')([card,cvc])')
    assert page.evaluate('guard.valid()')
    page.evaluate('let e=document.querySelector("#type");e.setAttribute("value","visa");getComputedStyle(card).opacity;e.removeAttribute("value")')
    return page.evaluate('guard.valid()')


@pytest.mark.parametrize('placement', ['plain', 'nested', 'adopted', 'imported'])
def test_matching_safe_readable_sheets_allow_hidden_update(guard_page, placement):
    sheet(guard_page, 'input {color:black}', placement)
    assert verdict(guard_page, _GUARD) is True


@pytest.mark.parametrize('placement', ['plain', 'nested', 'adopted', 'imported'])
@pytest.mark.parametrize('category,css', [
    ('scope', '@scope (form:has(#type[value="visa"])) {input {opacity:0}}'),
    ('scope', '@scope (body) to (#type[value="visa"]) {input {opacity:0}}'),
    ('scope', r'@scope (form:h\61s(#type[v\61lue="visa"])) {input {opacity:0}}'),
    ('container', '@container (max-width:200px) {input {opacity:0}}'),
    ('attribute', 'form:has(#type[value="visa"]) input {opacity:0}'),
    ('attribute', r'form:h\61s(#type[v\61lue="visa"]) input {opacity:0}'),
])
def test_each_recursive_css_predicate_is_load_bearing(guard_page, placement, category, css):
    sheet(guard_page, css, placement)
    assert verdict(guard_page, _GUARD) is False
    if category == 'scope':
        weakened = _GUARD.replace("!('start' in r) && !('end' in r) &&", 'true &&')
    elif category == 'container':
        weakened = _GUARD.replace("!('containerName' in r) &&", 'true &&').replace("!/^@container\\b/i.test(r.cssText || '')", 'true')
    else:
        weakened = _GUARD.replace('(!r.selectorText || !/:has\\s*\\(|\\[[^\\]]*\\b(?:style|value)\\b/i.test(decoded(r.selectorText)))', 'true')
    assert weakened != _GUARD
    # Same refusal assertion above becomes RED with ONLY its predicate removed.
    assert verdict(guard_page, weakened) is True


def test_opaque_sheet_readability_predicate_is_load_bearing(guard_page):
    sheet(guard_page, 'input {color:black}', 'opaque')
    assert verdict(guard_page, _GUARD) is False
    weakened = _GUARD.replace('catch {return false;}', 'catch {return true;}')
    assert weakened != _GUARD
    assert verdict(guard_page, weakened) is True
