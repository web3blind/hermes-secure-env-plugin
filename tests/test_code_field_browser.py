"""Disposable real browser; no external requests, pages or credentials."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes

UNKNOWN = '<form><input id="challenge" name="Code" inputmode="numeric" maxlength="8"></form>'


@pytest.mark.parametrize('explicit', [False, True])
def test_section_prefixed_otp_fill(nested, explicit):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',
                  '<form><input id="challenge" name="otp" autocomplete="section-login one-time-code"></form>')
    options = {'field_selector': '#challenge'} if explicit else {}
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, **options)[0]
    try:
        assert codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(target)

@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test')])
def test_registered_explicit_https(nested, sites, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested, sites, False, tmp_path, monkeypatch, field_selector='#challenge', markup=UNKNOWN)

@pytest.mark.parametrize('attr', ['placeholder', 'aria-label', 'label', 'aria-labelledby'])
@pytest.mark.parametrize('parent', [False, True])
def test_ru_sources_real(nested, attr, parent):
    origin, leaf = setup_chain(nested)
    if not parent:
        nested.page.goto('https://parent.test/leaf')
        leaf = nested.page
    if attr == 'label':
        markup = '<form><label>Введите код подтверждения<input name="Code"></label></form>'
    elif attr == 'aria-labelledby':
        markup = '<form><span id="label">Введите код подтверждения</span><input name="Code" aria-labelledby="label"></form>'
    else:
        markup = f'<form><input name="Code" {attr}="Введите код подтверждения"></form>'
    leaf.evaluate('(html)=>document.body.innerHTML=html', markup)
    targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, **({'parent': nested.parent} if parent else {}))
    assert len(targets) == 1
    try:
        assert codes.fill(targets[0], 'A!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(targets[0])

@pytest.mark.parametrize('attack', [
    'document.querySelector("input").replaceWith(document.querySelector("input").cloneNode())',
    'history.replaceState({},"","/other");history.replaceState({},"","/leaf")',
    'document.querySelector("form").setAttribute("action","/other")',
    'document.querySelector("input").setAttribute("name","password")',
])
def test_explicit_retained_authority(nested, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', UNKNOWN)
    assert codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent) == []
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')[0]
    try:
        leaf.evaluate(attack)
        with pytest.raises(ValueError):
            codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)

@pytest.mark.parametrize('markup,selector', [
    (UNKNOWN+UNKNOWN, 'input'),
    ('<form><input id="challenge" type="password" inputmode="numeric" maxlength="8"></form>', '#challenge'),
    ('<form><input id="challenge" name="promo" inputmode="numeric" maxlength="8"></form>', '#challenge'),
    ('<form><input id="challenge" autocomplete="cc-csc" inputmode="numeric" maxlength="8"></form>', '#challenge'),
    ('<form><input id="challenge" inputmode="numeric" maxlength="8" disabled></form>', '#challenge'),
    ('<form><input id="challenge" inputmode="numeric" maxlength="8" style="display:none"></form>', '#challenge'),
    ('<form><input id="challenge"></form>', '#challenge'),
    (UNKNOWN.replace('inputmode="numeric"', ''), '#challenge'),
    (UNKNOWN.replace('name="Code"', 'name="pin"'), '#challenge'),
    (UNKNOWN.replace('<form>', '<form><label for="challenge">API key</label>'), '#challenge'),
    (UNKNOWN.replace('maxlength="8"', 'maxlength="20"'), '#challenge'),
    (UNKNOWN.replace('<input', '<input readonly'), '#challenge'),
    (UNKNOWN.replace('<input', '<input type="hidden"'), '#challenge'),
    (UNKNOWN, '['),
    (UNKNOWN, 'form'),
])
def test_explicit_unsafe_refused(nested, markup, selector):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', markup)
    with pytest.raises(ValueError):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector=selector)

@pytest.mark.parametrize('wrapper', ['<fieldset disabled>{}</fieldset>', '<div inert>{}</div>'])
def test_effectively_disabled_selector_refused(nested, wrapper):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', wrapper.format(UNKNOWN))
    targets = []
    try:
        with pytest.raises(ValueError):
            targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')
    finally:
        for target in targets:
            codes.release(target)


def test_explicit_parent_root(nested):
    setup_chain(nested)
    nested.page.evaluate('(html)=>document.body.innerHTML=html', UNKNOWN)
    target = codes.discover('https://parent.test', 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')[0]
    try:
        assert target.ancestry == ()
        assert codes.fill(target, 'A!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(target)


def test_explicit_duplicate_in_other_document(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', UNKNOWN)
    nested.page.evaluate('(html)=>document.body.insertAdjacentHTML("beforeend",html)', UNKNOWN)
    with pytest.raises(ValueError):
        codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')


def test_explicit_expiry_and_release(nested, monkeypatch):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', UNKNOWN)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')[0]
    try:
        assert not codes.fill(target, 'A!7&z=R9', time.monotonic()-1)
        assert leaf.evaluate('document.querySelector("input").value === ""')
        from secure_env_ingress import nested_code
        monkeypatch.setattr(nested_code.time, 'monotonic', lambda: target.expires+1)
        with pytest.raises(ValueError):
            codes.assert_target(target)
    finally:
        codes.release(target)
    assert target.lease.closed


def test_registered_explicit_mutation_refuses(nested, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    attack = 'document.querySelector("iframe").contentDocument.querySelector("iframe").contentDocument.querySelector("input").outerHTML="<input id=challenge name=Code inputmode=numeric maxlength=8>"'
    run(nested, ('parent.test', 'parent.test'), False, tmp_path, monkeypatch, attack=attack, field_selector='#challenge', markup=UNKNOWN)
