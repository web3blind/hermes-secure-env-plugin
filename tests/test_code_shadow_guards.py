"""Shadow control authority negatives on real isolated Chromium."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes

ATTACKS = [
    'e.replaceWith(e.cloneNode(true))',
    'r.append(e)',
    'const p=e.parentNode;e.remove();p.append(e)',
    'document.body.appendChild(document.createElement("section")).append(r.host)',
    'e.form.action="/other"',
    'e.setAttribute("name","other");e.removeAttribute("name")',
    'r.append(e.cloneNode(true))',
    'document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"}).innerHTML="<input autocomplete=one-time-code>"',
]

@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('attack', ATTACKS)
def test_shadow_authority_change_refuses(nested, mode, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(mode)=>{document.querySelector("form").remove();const h=document.body.appendChild(document.createElement("div"));const r=h.attachShadow({mode});r.innerHTML="<form><input autocomplete=one-time-code></form>";window.fixtureRoot=r}', mode)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate('()=>{const r=window.fixtureRoot,e=r.querySelector("input");'+attack+'}')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(window.fixtureRoot.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)

@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('attack', [
    'e.replaceWith(e.cloneNode(true))',
    'r.append(e.cloneNode(true))',
    'r.querySelector("button").focus()',
    'document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"}).innerHTML="<input autocomplete=one-time-code>"',
])
def test_shadow_focus_attack_writes_nothing(nested, mode, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(mode)=>{document.querySelector("form").remove();const r=document.body.appendChild(document.createElement("div")).attachShadow({mode});r.innerHTML="<form><input autocomplete=one-time-code><button>Other</button></form>";window.fixtureRoot=r}', mode)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate('()=>{const r=window.fixtureRoot,e=r.querySelector("input");e.addEventListener("focus",()=>{'+attack+'},{once:true})}')
        try:
            written = codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        except ValueError:
            written = False  # CDP census refusals use the explicit-parent API exception.
        assert not written
        assert leaf.evaluate('Array.from(window.fixtureRoot.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


def test_existing_unselected_control_semantics_are_sticky(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.appendChild(document.createElement("input")).id="other"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate('const e=document.querySelector("#other");e.autocomplete="one-time-code";e.removeAttribute("autocomplete")')
        with pytest.raises(ValueError):
            codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)
