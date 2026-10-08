"""Sticky scoped authority and registered HTTPS regression coverage."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('selector', [None, '#otp'])
@pytest.mark.parametrize('mutation', [
    'e.setAttribute("class","changed");e.removeAttribute("class")',
    'e.form.method="post";e.form.removeAttribute("method")',
    'document.querySelector("#scope").setAttribute("aria-hidden","true");document.querySelector("#scope").removeAttribute("aria-hidden")',
    'document.querySelector("#name").firstChild.data="New label";document.querySelector("#name").firstChild.data="Verification code"',
    'document.body.insertAdjacentHTML("beforeend","<label for=otp>New label</label>");document.body.lastChild.remove()',
    'document.querySelector("#other").autocomplete="one-time-code";document.querySelector("#other").removeAttribute("autocomplete")',
    'document.body.insertAdjacentHTML("beforeend","<div id=otp></div>");document.body.lastChild.remove()',
])
def test_scoped_authority_changes_remain_sticky(nested, selector, mutation):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<section id=scope><form><label id=name>Verification code<input id=otp autocomplete=one-time-code></label></form></section><form><label>Address<input id=other></label></form>"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector=selector)[0]
    try:
        leaf.evaluate('()=>{const e=document.querySelector("#otp");'+mutation+'}')
        # A noncontrol duplicate matters only with an explicit selector.
        if mutation.startswith('document.body.insertAdjacentHTML') and 'div id=otp' in mutation and selector is None:
            assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        else:
            with pytest.raises(ValueError):
                codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
            assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


def test_compound_selector_transient_ambiguity_is_sticky(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.querySelector("input").id="otp";document.querySelector("input").className="challenge";document.body.insertAdjacentHTML("beforeend","<div id=other class=other></div>")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#otp.challenge')[0]
    try:
        leaf.evaluate('const e=document.querySelector("#other");e.id="otp";e.className="challenge";e.id="other";e.className="other"')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


def test_relational_selector_reverted_child_dependency_is_sticky(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.querySelector("input").id="otp"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='form:not(:has(span)) input')[0]
    try:
        leaf.evaluate('const f=document.querySelector("form");const s=f.appendChild(document.createElement("span"));s.remove()')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


def test_late_root_in_other_matching_document_is_ambiguous(nested):
    origin, leaf = setup_chain(nested)
    nested.pages[origin+'/other'] = '<div id=late></div>'
    nested.page.evaluate('(url)=>{const f=document.body.appendChild(document.createElement("iframe"));f.src=url}', origin+'/other')
    deadline = time.monotonic()+15
    while not any(f.url == origin+'/other' for f in nested.page.frames):
        assert time.monotonic() < deadline
        nested.page.wait_for_timeout(50)
    other = next(f for f in nested.page.frames if f.url == origin+'/other')
    other.wait_for_selector('#late', state='attached')
    leaf.evaluate('document.querySelector("input").id="otp"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#otp')[0]
    try:
        other.evaluate('document.querySelector("#late").attachShadow({mode:"closed"}).innerHTML="<div id=otp></div>"')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


@pytest.mark.parametrize('mode', ['open', 'closed'])
def test_late_decorative_root_is_observed_after_adoption(nested, mode):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.querySelector("input").id="otp";document.body.insertAdjacentHTML("beforeend","<div id=late></div>")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#otp')[0]
    try:
        leaf.evaluate('(mode)=>{window.lateRoot=document.querySelector("#late").attachShadow({mode});window.lateRoot.innerHTML="<span>Decoration</span>"}', mode)
        codes.assert_target(target)
        leaf.evaluate('const e=window.lateRoot.querySelector("span");e.id="otp";e.removeAttribute("id")')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


def test_registered_focus_unrelated_form_mutation_fills(nested, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested, ('parent.test', 'leaf.test'), False, tmp_path, monkeypatch,
        field_selector='#otp', shadow_mode='closed',
        markup='<form onsubmit="window.submitted=true;return false"><input id=otp autocomplete=one-time-code onfocus="document.querySelector(\'#other\').className=\'updated\';document.querySelector(\'#otherlabel\').textContent=\'Address\'"></form><form><label id=otherlabel>Street</label><input id=other></form>')


@pytest.mark.parametrize('attack', [
    'const d=document.querySelector("iframe").contentDocument.querySelector("iframe").contentDocument;d.head.insertAdjacentHTML("beforeend","<base href=https://foreign.test/>");d.querySelector("base").remove()',
    'const d=document.querySelector("iframe").contentDocument.querySelector("iframe").contentDocument;d.querySelector("#late").attachShadow({mode:"closed"}).innerHTML="<div id=otp></div>"',
])
def test_registered_wait_sticky_refuses(nested, tmp_path, monkeypatch, attack):
    from test_nested_code import test_registered_nested_https as run
    run(nested, ('parent.test', 'parent.test'), False, tmp_path, monkeypatch,
        field_selector='#otp', attack=attack,
        markup='<form action=verify><input id=otp autocomplete=one-time-code></form><div id=late></div>')
