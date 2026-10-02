"""Actual captured CSS/topology empty-form RED and reserved-slot attacks."""
import pytest

from computop_fixture import MANIFEST, ROOT, markup, ready
from secure_env_ingress.payment_fill import _GUARD

pytest_plugins = ['test_payment_dynamic_guard']


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
        assert page.evaluate('(i)=>guard.focus(i)', i)
        assert page.evaluate('([i,v,t])=>guard.write(i,v,t)', [i, v, token]) == dict(written=True, valid=True)


@pytest.mark.parametrize('painting', [
    'border-image-source:linear-gradient(black,black);border-image-slice:1;border-image-width:1000px;border-image-outset:1000px',
    '-webkit-box-reflect:below 100px',
])
@pytest.mark.parametrize('visible', [False, True])
@pytest.mark.parametrize('delivery', ['inline', 'stylesheet', 'latent'])
def test_out_of_slot_paint_refuses_show_revert(provider, painting, visible, delivery):
    if delivery == 'inline':
        provider.evaluate('(css)=>brand_visa.firstElementChild.style.cssText=css', painting)
    else:
        selector = '.brand img' if delivery == 'stylesheet' else '.brand:hover img'
        provider.add_style_tag(content=selector + '{' + painting + '}')
    if visible:
        provider.evaluate("brand_visa.style.display='flex'")
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex';brand_visa.getBoundingClientRect();brand_visa.style.display='none'")
    assert provider.evaluate('guard.valid()') is False
    assert provider.evaluate('guard.focus(2)') is False


@pytest.mark.parametrize('delivery', ['stylesheet', 'imported', 'adopted'])
@pytest.mark.parametrize('selector,effect', [
    ('#cccvc:focus ~ .custom-input-info', 'transform:scale(100)'),
    ('#cccvc:nth-child(1 of :focus) ~ .custom-input-info', '--activation:1'),
    (r'#cccvc:f\6f cus ~ .custom-input-info', '-webkit-box-reflect:below 100px'),
    ('.custom-input-wrapper:focus-within .custom-input-info', 'position:fixed;inset:0'),
    ('.custom-input-label, #cccvc:focus ~ .custom-input-info', 'transform:translateY(-0.25rem) scale(0.75)'),
])
def test_control_state_sibling_overlay_refuses(provider, delivery, selector, effect):
    css = '.custom-input-info {width:24px;height:24px;background:black} ' + selector + '{' + effect + '}'
    if delivery == 'stylesheet':
        provider.add_style_tag(content=css)
    elif delivery == 'imported':
        provider.route('https://www.computop-paygate.com/overlay.css', lambda r: r.fulfill(body=css, content_type='text/css'))
        provider.add_style_tag(content='@import url("/overlay.css");')
        provider.wait_for_function("Array.from(document.styleSheets).some(s=>Array.from(s.cssRules).some(r=>r.styleSheet && r.styleSheet.cssRules.length===2))")
    else:
        provider.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False
    assert provider.evaluate('guard.focus(3)') is False


@pytest.mark.parametrize('delivery', ['stylesheet', 'imported', 'adopted'])
@pytest.mark.parametrize('kind', ['mixed', 'custom_property', 'opacity', 'visibility'])
def test_mixed_and_indirect_activation_overlays_refuse(provider, delivery, kind):
    from computop_fixture import overlay_attack
    css = overlay_attack(kind)
    if delivery == 'stylesheet':
        provider.add_style_tag(content=css)
    elif delivery == 'imported':
        provider.route('https://www.computop-paygate.com/activation.css', lambda r: r.fulfill(body=css, content_type='text/css'))
        provider.add_style_tag(content='@import url("/activation.css");')
        provider.wait_for_function("Array.from(document.styleSheets).some(s=>Array.from(s.cssRules).some(r=>r.styleSheet && r.styleSheet.cssRules.length===2))")
    else:
        provider.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False
    assert provider.evaluate('guard.focus(3)') is False


@pytest.mark.parametrize('delivery', ['stylesheet', 'imported', 'adopted'])
def test_label_descendants_do_not_inherit_floating_label_capability(provider, delivery):
    css = ('#cccvc ~ label span {position:absolute;left:0;top:0;right:auto;'
           'width:24px;height:24px;margin:0;background:currentColor;color:transparent;z-index:10000;'
           'pointer-events:none} '
           '#cccvc:focus ~ label span {color:black}')
    if delivery == 'stylesheet':
        provider.add_style_tag(content=css)
    elif delivery == 'imported':
        provider.route('https://www.computop-paygate.com/child.css', lambda r: r.fulfill(body=css, content_type='text/css'))
        provider.add_style_tag(content='@import url("/child.css");')
        provider.wait_for_function("Array.from(document.styleSheets).some(s=>Array.from(s.cssRules).some(r=>r.styleSheet && r.styleSheet.cssRules.length===2))")
    else:
        provider.evaluate('(css)=>{const s=new CSSStyleSheet();s.replaceSync(css);document.adoptedStyleSheets=[s]}', css)
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False


@pytest.mark.parametrize('effect', [
    '--activation:1', 'opacity:1', 'visibility:visible', 'transform:scale(100)',
    'filter:blur(100px)', 'color:var(--paint)',
])
def test_provider_button_cosmetic_exception_does_not_grant_activation(provider, effect):
    provider.add_style_tag(content='form:invalid button.custom-button-red {' + effect + '}')
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False


@pytest.mark.parametrize('css', [
    'form:invalid .custom-input-info {color:red}',
    'form:invalid .custom-button-red, form:invalid .custom-input-info {color:red}',
    'button.custom-button-red {position:fixed;inset:0;width:100vw;height:100vh}',
    'button.custom-button-red {text-shadow:0 0 1000px black}',
    'button.custom-button-red {-webkit-text-stroke:1000px black}',
    'button.custom-button-red {outline:1000px solid black}',
    'button.custom-button-red {height:44px;font-size:1000px}',
])
def test_button_cosmetic_exception_requires_all_actual_bounded_subjects(provider, css):
    provider.add_style_tag(content=css)
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False


def test_button_cosmetic_exception_does_not_cover_descendant_paint(provider):
    provider.evaluate("document.querySelector('button').innerHTML='<span style=\"position:fixed;inset:0;background:currentColor\">Pay</span>'")
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex'")
    assert provider.evaluate('guard.valid()') is False


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


@pytest.mark.parametrize('css', [
    '.brand {position:static}', '.brand {min-width:400px}', '.brand {min-height:400px}',
    '.brand {right:100px}', '.brand {margin-left:-400px}',     '.brand:hover {width:1000px}',
    '@namespace h url("http://www.w3.org/1999/xhtml"); h|div:hover {width:1000px}',
    '.brand:hover {min-height:1000px}',
    '.brand:hover {right:500px}',
    '.custom-input-wrapper:hover {width:1000px}',
    '.custom-input:hover {width:1000px}',
    '.custom-input:hover {box-shadow:0 0 1000px 1000px black}',
    '.custom-input-label:hover {transform:scale(100)}',
    '.custom-input-label:hover {top:1000px}',
    '.brand {transform:scale(100)}',
    '.brand:hover {transform:scale(100)}', '.brand img {box-shadow:0 0 1000px 1000px black}',
    '.brand::before {content:"";position:fixed;inset:0;background:white}',
    '.brand img::after {content:"evil"}', '.brand {animation:grow 1s infinite} @keyframes grow {to {transform:scale(100)}}',
    '.brand {transition:transform 1s}', '.custom-input-wrapper {transform:scale(2)}',
    '#_KKnr {padding-right:14px}',
])
def test_unsafe_latent_slot_never_receives_exception(provider, css):
    provider.add_style_tag(content=css)
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex';brand_visa.getBoundingClientRect();brand_visa.style.display='none'")
    assert provider.evaluate('guard.valid()') is False


@pytest.mark.parametrize('mutation,undo', [
    ("brand_visa.style.right='200px'", "brand_visa.removeAttribute('style')"),
    ("brand_visa.style.right='200px'", "brand_visa.removeAttribute('style');brand_visa.style.display='flex'"),
    ("brand_visa.style.right='200px'", "brand_visa.style.cssText='display:flex'"),
    ("brand_visa.style.position='static'", "brand_visa.removeAttribute('style')"),
    ("brand_visa.style.transform='scale(100)'", "brand_visa.removeAttribute('style')"),
    ("brand_visa.style.display='block'", "brand_visa.removeAttribute('style')"),
    ("brand_visa.firstChild.src='data:,'", "brand_visa.firstChild.src=source"),
    ("brand_visa.firstChild.tabIndex=0", "brand_visa.firstChild.removeAttribute('tabindex')"),
    ("_KKnr.disabled=true", "_KKnr.disabled=false"),
    ("_KKnr.readOnly=true", "_KKnr.readOnly=false"),
    ("_KKnr.name='other'", "_KKnr.name='_KKnr'"),
    ("document.querySelector('form').action='/evil'", "document.querySelector('form').removeAttribute('action')"),
    ("document.querySelector('label').textContent='Other purpose'", "document.querySelector('label').innerHTML=label"),
    ("brand_visa.remove();_KKnr.parentElement.append(savedBrand)", ""),
])
def test_slot_and_semantics_reverted_stay_sticky(provider, mutation, undo):
    bind(provider)
    provider.evaluate('''([mutation,undo])=>{
      const source=brand_visa.firstChild.src,label=document.querySelector('label').innerHTML;
      new Function('savedBrand',mutation)(brand_visa);brand_visa.getBoundingClientRect();
      new Function('source','label',undo)(source,label);
    }''', [mutation,undo])
    assert provider.evaluate('guard.valid()') is False
    assert provider.evaluate('guard.focus(2)') is False


@pytest.mark.parametrize('css', [
    'form:has([name=KKName][value=VISA]) input {opacity:0}',
    '.brand[style] ~ label {display:none}',
    '@scope (form:has([value=VISA])) {input {opacity:0}}',
    '@container (width>1px) {input {opacity:0}}',
])
def test_global_selector_policy_still_rejects_reverted_updates(provider, css):
    provider.add_style_tag(content=css)
    bind(provider)
    provider.evaluate("document.SSLForm.KKName.setAttribute('value','VISA');document.SSLForm.KKName.removeAttribute('value')")
    assert provider.evaluate('guard.valid()') is False


def test_opaque_css_never_gets_reserved_slot_exception(provider):
    provider.route('https://opaque.test/style.css', lambda r: r.fulfill(body='input {color:black}', content_type='text/css'))
    provider.add_style_tag(url='https://opaque.test/style.css')
    bind(provider)
    provider.evaluate("brand_visa.style.display='flex';brand_visa.getBoundingClientRect();brand_visa.style.display='none'")
    assert provider.evaluate('guard.valid()') is False


def test_reserved_slot_cssom_identity_changes_stick(provider):
    bind(provider)
    provider.evaluate("document.styleSheets[3].insertRule('.brand {color:red}',0)")
    assert provider.evaluate('guard.valid()') is False
    provider.evaluate('document.styleSheets[3].deleteRule(0)')
    assert provider.evaluate('guard.valid()') is False


def test_inspection_never_gets_div_display_exception(provider):
    provider.evaluate('window.guard=(' + _GUARD + ')([creditCardHolder,_KKnr,expiry_date,cccvc],true)')
    assert provider.evaluate('guard.valid()')
    provider.evaluate("brand_visa.style.display='flex';brand_visa.style.display='none'")
    assert provider.evaluate('guard.valid()') is False
