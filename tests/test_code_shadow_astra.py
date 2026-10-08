"""Exact Astra regressions against isolated actual Chromium, synthetic codes only."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def issue(nested, leaf, origin, selector=None):
    return codes.discover(origin, 'Synthetic', nested.sup.task_id,
                          parent=nested.parent, field_selector=selector)[0]


def refuses(target, leaf):
    with pytest.raises(ValueError):
        codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
    assert leaf.evaluate('document.querySelector("input").value===""')


@pytest.mark.parametrize('revert', [False, True])
def test_effective_action_base_sticky(nested, revert):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.head.innerHTML="<base href=https://parent.test/old/>";document.querySelector("form").setAttribute("action","verify")')
    target = issue(nested, leaf, origin)
    try:
        leaf.evaluate('(revert)=>{const b=document.querySelector("base");b.href="https://foreign.test/";if(revert)b.href="https://parent.test/old/"}', revert)
        refuses(target, leaf)
    finally:
        codes.release(target)


@pytest.mark.parametrize('selector', [None, '#otp'])
@pytest.mark.parametrize('mutation', [
    'document.querySelector("#decor").className="updated"',
    'document.querySelector("#other").className="updated";document.querySelector("#otherlabel").textContent="Your address"',
    'document.querySelector("#other").placeholder="Street address"',
    'document.querySelector("#otherform").insertAdjacentHTML("beforeend","<label>City<input name=city></label>")',
])
def test_unrelated_form_and_selector_changes_are_harmless(nested, selector, mutation):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.querySelector("input").id="otp";document.body.insertAdjacentHTML("beforeend","<div id=decor></div><form id=otherform><label id=otherlabel>Address<input id=other name=address></label></form>")')
    target = issue(nested, leaf, origin, selector)
    try:
        leaf.evaluate('()=>{'+mutation+'}')
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("#otp").value==="Q!7&z=R9" && Array.from(document.querySelectorAll("#otherform input")).every(e=>e.value==="") && !window.submitted')
    finally:
        codes.release(target)


@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('attribute', ['style', 'aria-hidden'])
def test_intermediate_composed_iframe_ancestor_is_sticky(nested, mode, attribute):
    origin, leaf = setup_chain(nested)
    nested.page.evaluate('(mode)=>{const frame=document.querySelector("iframe");const outer=document.body.appendChild(document.createElement("div")).attachShadow({mode});const ancestor=outer.appendChild(document.createElement("section"));const inner=ancestor.appendChild(document.createElement("div")).attachShadow({mode});inner.append(frame);window.fixtureAncestor=ancestor}', mode)
    deadline = time.monotonic()+15
    while not any(f.url == origin+'/leaf' for f in nested.page.frames):
        assert time.monotonic() < deadline
        nested.page.wait_for_timeout(50)
    leaf = next(f for f in nested.page.frames if f.url == origin+'/leaf')
    leaf.wait_for_selector('input')
    target = issue(nested, leaf, origin)
    try:
        nested.page.evaluate('(attribute)=>{const e=window.fixtureAncestor;e.setAttribute(attribute,attribute==="style"?"opacity:0":"true");e.removeAttribute(attribute)}', attribute)
        refuses(target, leaf)
    finally:
        codes.release(target)


def test_transient_accessible_name_of_other_control_is_sticky(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.insertAdjacentHTML("beforeend","<form><div id=othername>Address</div><input aria-labelledby=othername></form>")')
    target = issue(nested, leaf, origin)
    try:
        leaf.evaluate('const e=document.querySelector("#othername");e.textContent="Verification code";e.textContent="Address"')
        refuses(target, leaf)
    finally:
        codes.release(target)


@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('markup', ['<div id=otp></div>', '<input autocomplete=one-time-code>', '<span>Decoration</span>'])
def test_late_root_enters_uniqueness_and_authority_census(nested, mode, markup):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.querySelector("input").id="otp";document.body.insertAdjacentHTML("beforeend","<div id=late></div>")')
    target = issue(nested, leaf, origin, '#otp')
    try:
        leaf.evaluate('([mode,markup])=>{window.lateRoot=document.querySelector("#late").attachShadow({mode});window.lateRoot.innerHTML=markup}', [mode, markup])
        if markup.startswith('<span'):
            codes.assert_target(target)
            leaf.evaluate('window.lateRoot.querySelector("span").className="tooltip"')
            assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
            assert leaf.evaluate('document.querySelector("#otp").value==="Q!7&z=R9" && !window.submitted')
        else:
            refuses(target, leaf)
    finally:
        codes.release(target)
