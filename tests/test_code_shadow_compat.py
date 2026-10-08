"""Synthetic Chromium compatibility and immutable shadow code authority."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes

@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('hosted', [False, True])
@pytest.mark.parametrize('explicit_parent', [False, True])
def test_shadow_code_fill(nested, mode, hosted, explicit_parent):
    origin, leaf = setup_chain(nested)
    if not explicit_parent:
        nested.page.goto(origin+'/leaf')
        leaf = nested.page
    leaf.evaluate('([mode,hosted])=>{const h=document.createElement("div");document.body.append(h);const r=h.attachShadow({mode});r.innerHTML=hosted?"<form><input id=challenge autocomplete=one-time-code></form>":"<span>Tooltip</span>";if(hosted)document.querySelector("form").remove();window.fixtureRoot=r}', [mode, hosted])
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, **({'parent':nested.parent} if explicit_parent else {}))[0]
    try:
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('(hosted)=>(hosted?window.fixtureRoot:document).querySelector("input").value==="Q!7&z=R9"', hosted)
    finally:
        codes.release(target)

@pytest.mark.parametrize('mutation', [
    'document.body.append(document.createElement("span"))',
    'document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"}).innerHTML="<span>Tooltip</span>"',
    'document.querySelector("form").appendChild(document.createElement("span")).textContent="Countdown"',
])
def test_unrelated_ui_mutation_does_not_block(nested, mutation):
    origin, leaf = setup_chain(nested)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate(mutation)
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(target)

@pytest.mark.parametrize('case', ['deep', 'large'])
def test_unrelated_content_capacity(nested, case):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(kind)=>{const x=document.createElement("section");document.body.append(x);x.innerHTML=kind==="deep"?"<div>".repeat(50)+"Decoration"+"</div>".repeat(50):"<span></span>".repeat(2200)}', case)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
    finally:
        codes.release(target)


def test_independent_shadow_roots_are_not_split_boxes(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('()=>{document.querySelector("form").remove();for(let i=0;i<6;i++){const r=document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"});r.innerHTML="<input autocomplete=one-time-code maxlength=1>"}}')
    targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
    try:
        assert len(targets) == 6
        for target in targets:
            assert len(target.controls) == 1
    finally:
        for target in targets:
            codes.release(target)


@pytest.mark.parametrize('mode', ['open', 'closed'])
@pytest.mark.parametrize('explicit', [False, True])
@pytest.mark.parametrize('split', [False, True])
def test_registered_shadow_https(nested, mode, explicit, split, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested, ('parent.test', 'leaf.test'), split, tmp_path, monkeypatch,
        shadow_mode=mode, field_selector='input' if explicit and not split else None)


def test_top_level_refusal_preserves_false_result(nested):
    origin, _ = setup_chain(nested)
    nested.page.goto(origin+'/leaf')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id)[0]
    try:
        nested.page.evaluate('document.querySelector("input").replaceWith(document.querySelector("input").cloneNode(true))')
        assert not codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert nested.page.locator('input').input_value() == ''
    finally:
        codes.release(target)

