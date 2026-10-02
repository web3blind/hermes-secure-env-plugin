"""Fixed-space host acceptance and legacy layout counterexamples, real Chromium."""
import pytest

from payment_fixture_helpers import HOST

pytest_plugins = ['test_payment_dynamic_guard']


def bind(page):
    from test_payment_dynamic_guard import bind as bind_guard
    bind_guard(page)


@pytest.mark.parametrize('layout', ['block', 'flex', 'grid'])
def test_fixed_space_host_maintains_controls_and_allows_toggle(guard_page, layout):
    page = guard_page
    page.evaluate(HOST)
    if layout != 'block':
        page.evaluate('(layout)=>{const f=document.querySelector("form");f.style.display=layout;if(layout==="grid")f.style.gridTemplateColumns="200px 200px 200px 24px"}', layout)
    bind(page)
    assert page.evaluate('''() => {
      const before=[card,cvc,host].map(e=>JSON.stringify(e.getBoundingClientRect()));
      brand.style.display='block';brand.getBoundingClientRect();
      const after=[card,cvc,host].map(e=>JSON.stringify(e.getBoundingClientRect()));
      document.querySelector('#type').setAttribute('value','visa');
      brand.style.display='none';brand.getBoundingClientRect();
      return before.every((r,i)=>r===after[i]) && guard.valid();
    }''')


@pytest.mark.parametrize('revert', [False, True])
@pytest.mark.parametrize('layout', [
    'brand.style.marginLeft="-24px";cvc.style.width="24px"',
    'document.querySelector("form").style.cssText="width:420px;height:24px;overflow:hidden"',
    'document.querySelector("form").style.display="flex"',
    'document.querySelector("form").style.display="grid"',
    'brand.style.minWidth="400px"',
    'brand.style.minHeight="400px"',
])
def test_legacy_normal_flow_layout_never_gets_exception(guard_page, layout, revert):
    page = guard_page
    # Static CSS, not inline mutation, evades the old icon declaration whitelist.
    page.evaluate('(layout)=>{eval(layout);const css=brand.style.cssText;brand.removeAttribute("style");const s=document.createElement("style");s.textContent="#brand {"+css+"}";document.head.append(s);brand.style.cssText="display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint"}', layout)
    bind(page)
    page.evaluate('(revert)=>{brand.style.display="inline-block";brand.getBoundingClientRect();if(revert)brand.style.display="none"}', revert)
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('setup', [
    'host.style.marginLeft="-24px"',
    'host.style.contain="paint"',
    'host.style.overflow="visible"',
    'host.style.minWidth="400px"',
    'host.style.maxWidth="none"',
    'host.style.flex="1 1 auto"',
    'host.style.transform="translateX(-24px)"',
    'host.style.outline="40px solid black"',
    'brand.style.minWidth="400px"',
    'brand.style.marginLeft="-24px"',
    'brand.style.position="static"',
    'brand.style.left="-24px"',
])
def test_invalid_host_or_hidden_geometry_refuses(guard_page, setup):
    page = guard_page
    page.evaluate(HOST)
    page.evaluate('()=>{' + setup + '}')
    bind(page)
    page.evaluate('brand.style.display="block";brand.getBoundingClientRect();brand.style.display="none"')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('target', ['card', 'cvc', 'label'])
def test_fixed_host_must_be_disjoint_from_controls_and_labels(guard_page, target):
    page = guard_page
    page.evaluate(HOST)
    assert page.evaluate('''target => {
      const t=target==='label' ? document.querySelector('label') : document.getElementById(target);
      const hr=host.getBoundingClientRect(), tr=t.getBoundingClientRect();
      host.style.left=(tr.left-hr.left)+'px';host.style.top=(tr.top-hr.top)+'px';
      const r=host.getBoundingClientRect();
      return r.right>tr.left && r.left<tr.right && r.bottom>tr.top && r.top<tr.bottom;
    }''', target)
    bind(page)
    page.evaluate('brand.style.display="block";brand.getBoundingClientRect();brand.style.display="none"')
    assert page.evaluate('guard.valid()') is False


@pytest.mark.parametrize('mutation', [
    'host.style.display="none"',
    'host.style.left="-24px"',
    'host.style.overflow="visible"',
    'host.style.contain="none"',
    'host.style.minWidth="400px"',
    'document.querySelector("form").style.display="flex"',
    'host.remove();document.querySelector("form").append(host)',
])
def test_bound_host_and_ancestry_reverted_mutations_are_sticky(guard_page, mutation):
    page = guard_page
    page.evaluate(HOST)
    bind(page)
    page.evaluate('''mutation => {
      const hs=host.getAttribute('style'),f=document.querySelector('form'),fs=f.getAttribute('style');
      // Controlled literal mutations; no page/user supplied executable text.
      const execute=new Function('host',mutation);execute(host);host.getBoundingClientRect();
      host.setAttribute('style',hs);if(fs===null)f.removeAttribute('style');else f.setAttribute('style',fs);
    }''', mutation)
    assert page.evaluate('guard.valid()') is False
    assert page.evaluate('guard.focus(0)') is False



@pytest.mark.parametrize('mutation', [
    'host.style.width="60px"', 'host.style.marginLeft="-24px"',
    'host.parentElement.style.padding="20px"',
])
def test_host_and_ancestry_are_sticky_authority(guard_page, mutation):
    page = guard_page
    page.evaluate(HOST)
    bind(page)
    page.evaluate('()=>{const e=' + ('host.parentElement' if 'parentElement' in mutation else 'host') + ';const old=e.getAttribute("style");' + mutation + ';if(old===null)e.removeAttribute("style");else e.setAttribute("style",old)}')
    assert page.evaluate('guard.valid()') is False
