"""Synthetic retained targets; no real browser profile or credentials."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def spec(n=1, layout='single', multiline=False):
    s = {'version': 1, 'purpose': 'transient_code', 'layout': layout,
         'validation': {'charset': 'unicode_text' if multiline else 'ascii_printable_no_space',
                        'exact_length': n, 'multiline': multiline}}
    if layout == 'indexed_cells':
        s.update(group='#group', field_selector='input', order='dom', expected_count=n)
    else:
        s['fields'] = [{'selector': '#challenge'}] if layout == 'single' else [{'selector': f'#c{i}'} for i in reversed(range(n))]
    return s






@pytest.mark.parametrize('markup,value,multiline', [
    ('<input id="challenge">', '!', False),
    ('<textarea id="challenge"></textarea>', 'A\nБ', True),
    ('<div id="challenge" contenteditable="plaintext-only"></div>', 'A\nБ', True),
    ('<div id="challenge" contenteditable="true"></div>', 'A\nБ', True),
])
def test_adapters(nested, markup, value, multiline):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML=s', markup)
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(len(value), multiline=multiline))[0]
    try:
        assert codes.fill(t, value, time.monotonic()+30)
        assert leaf.evaluate('(()=>{const e=document.querySelector("#challenge");return e.value??e.textContent})()') == value
    finally:
        codes.release(t)


@pytest.mark.parametrize('attack', [
    'document.querySelector("#challenge").replaceWith(document.querySelector("#challenge").cloneNode())',
    'document.querySelector("#challenge").id="other";document.querySelector("input").id="challenge"',
    'history.replaceState({},"","/other");history.replaceState({},"","/leaf")',
    'document.querySelector("#challenge").setAttribute("aria-label","password");document.querySelector("#challenge").removeAttribute("aria-label")',
    'document.body.append(document.querySelector("#challenge").cloneNode());document.body.lastChild.remove()',
])
def test_authority_history(nested, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate(attack)
        with pytest.raises(ValueError):
            codes.fill(t, '!', time.monotonic()+30)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    finally:
        codes.release(t)


@pytest.mark.parametrize('markup', [
    '<input id="challenge" name="password">', '<input id="challenge" autocomplete="cc-csc">',
    '<input id="challenge" type="number">', '<input id="challenge" type="password">',
    '<input id="challenge" disabled>', '<input id="challenge"><input id="challenge">',
    '<form action="https://other.test"><input id="challenge"></form>',
    '<input id="challenge" name="apiKey">', '<input id="challenge" name="email">',
    '<input id="challenge" name="pwd">', '<input id="challenge" name="apiToken">',
    '<input id="challenge" name="user_name">', '<input id="challenge" name="refresh_token">',
    '<div aria-label="Card payment"><input id="challenge"></div>',
    '<input id="challenge" name="recoverySeed">',
    '<input id="challenge" name="captcha">',
    '<canvas id="challenge"></canvas>',
    '<div id="challenge" contenteditable="true"><br></div>',
    '<div contenteditable="true"><div id="challenge" contenteditable="true"></div></div>',
    '<div id="challenge" contenteditable="plaintext-only"><b>rich</b></div>',
])
def test_unsupported_refuses(nested, markup):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML=s', markup)
    with pytest.raises(ValueError):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())






@pytest.mark.parametrize('event', ['focus', 'input'])
def test_exact_callback_refusal(nested, event):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group><input maxlength=1><input maxlength=1></div>"')
    leaf.evaluate('(event)=>document.querySelector("input").addEventListener(event,()=>{const e=document.querySelectorAll("input")[1];e.setAttribute("name","password");e.removeAttribute("name")},{once:true})', event)
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(2, 'indexed_cells'))[0]
    try:
        try:
            assert not codes.fill(t, '!?', time.monotonic()+30)
        except ValueError:
            pass
        assert leaf.evaluate('document.querySelectorAll("input")[1].value===""')
        if event == 'focus':
            assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(t)


def test_plaintext_transient_text_refuses(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=challenge contenteditable=plaintext-only>original</div>"')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate('const n=document.querySelector("#challenge").firstChild;n.data="changed";n.data="original"')
        with pytest.raises(ValueError):
            codes.fill(t, '!', time.monotonic()+30)
        assert leaf.evaluate('document.querySelector("#challenge").textContent==="original"')
    finally:
        codes.release(t)


@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('markup', ['<input id=challenge>', '<textarea id=challenge></textarea>', '<div id=challenge contenteditable=plaintext-only></div>', '<div id=challenge contenteditable=true></div>'])
def test_exact_shadow_nonmutating(nested, mode, markup):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('([mode,markup])=>{document.body.innerHTML="<div id=host></div>";window.fixtureRoot=document.querySelector("#host").attachShadow({mode});window.fixtureRoot.innerHTML=markup}', [mode, markup])
    before = leaf.evaluate('window.fixtureRoot.innerHTML')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec())[0]
    try:
        assert leaf.evaluate('window.fixtureRoot.innerHTML') == before
        assert codes.fill(t, '!', time.monotonic()+30)
        assert leaf.evaluate('(()=>{const e=window.fixtureRoot.querySelector("#challenge");return e.value??e.textContent})()') == '!'
    finally:
        codes.release(t)







