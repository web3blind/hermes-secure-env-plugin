"""Actual captured CSS/topology empty-form RED and reserved-slot attacks."""
import pytest

from computop_fixture import MANIFEST, ROOT, markup, ready
from secure_env_ingress.payment_fill import _GUARD

from legacy_payment_dynamic_guard import chromium as chromium


@pytest.fixture
def provider(chromium):
    context = chromium.new_context(viewport={'width': 576, 'height': 334})
    page = context.new_page()
    def route(r):
        row = next((a for a in MANIFEST if a['url'] == r.request.url), None)
        if row:
            ct = 'text/css' if row['name'].endswith('.css') else 'image/svg+xml' if row['name'].endswith('.svg') else 'font/woff2'
            r.fulfill(body=(ROOT / row['name']).read_bytes(), content_type=ct)
        elif r.request.url.endswith('/fields'):
            r.fulfill(body=markup(), content_type='text/html')
        else:
            r.fulfill(status=404, body='')
    context.route('**/*', route)
    page.goto('https://www.computop-paygate.com/fields')
    ready(page)
    yield page
    context.close()


def bind(page):
    page.evaluate('window.guard=(' + _GUARD + ')([creditCardHolder,_KKnr,expiry_date,cccvc])')
    assert page.evaluate('guard.valid()')


def fill(page):
    for i, (v, token) in enumerate([('Synthetic Holder', 'cc-name'), ('4242424242424242', 'cc-number'), ('12/31', 'cc-exp'), ('123', 'cc-csc')]):
        assert page.evaluate('([i,v,t])=>guard.write(i,v,t)', [i, v, token]) == dict(written=True, valid=True)
















def test_unrelated_widget_state_effects_do_not_block_empty_fill(provider):
    provider.evaluate("document.body.insertAdjacentHTML('beforeend','<div class=unrelated><button>Widget</button><span></span></div>')")
    provider.add_style_tag(content='.unrelated button:focus ~ span {transform:scale(100)} .unrelated:hover {box-shadow:0 0 1000px black}')
    bind(provider)
    fill(provider)
    assert provider.evaluate('guard.valid()')


def test_empty_captured_css_topology_completes_four_fields(provider):
    assert provider.evaluate("[creditCardHolder,_KKnr,expiry_date,cccvc].every(e=>e.value==='')")
    assert provider.evaluate("_KKnr.getBoundingClientRect().height===48 && getComputedStyle(_KKnr).paddingRight==='70px'")
    bind(provider)
    fill(provider)
    assert provider.evaluate("creditCardHolder.value==='Synthetic Holder' && _KKnr.value==='4242 4242 4242 4242' && expiry_date.value==='12/31' && cccvc.value==='123' && document.SSLForm.KKName.value==='VISA' && !check_agb.checked && submissions===0")
