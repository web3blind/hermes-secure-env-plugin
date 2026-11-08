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


def test_russian_secret_code_label_is_transient_code_not_a_secret_key(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML=s', '<input id="challenge" placeholder="Секретный код">')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(6))[0]
    try:
        assert codes.fill(t, '123456', time.monotonic()+30)
        assert leaf.evaluate('document.querySelector("#challenge").value') == '123456'
    finally:
        codes.release(t)


@pytest.mark.parametrize('label', ['Секретный ключ', 'Секретный код восстановления'])
def test_secret_key_labels_remain_forbidden(nested, label):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(s)=>document.body.innerHTML=s', '<input id="challenge" placeholder="'+label+'">')
    with pytest.raises(ValueError):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(6))




@pytest.mark.parametrize('markup', [
    '<input id="challenge" name="password">', '<input id="challenge" autocomplete="cc-csc">',
    '<input id="challenge" type="number">', '<input id="challenge" type="password">',
    '<input id="challenge" disabled>', '<input id="challenge"><input id="challenge">',
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
