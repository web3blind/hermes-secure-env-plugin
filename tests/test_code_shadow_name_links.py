"""Accessible-name link changes must stay sticky without blocking other UI."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('explicit_parent', [False, True])
@pytest.mark.parametrize('revert', [False, True])
def test_external_name_id_link_is_sticky(nested, explicit_parent, revert):
    origin, leaf = setup_chain(nested)
    if not explicit_parent:
        nested.page.goto(origin+'/leaf')
        leaf = nested.page
    leaf.evaluate('document.body.insertAdjacentHTML("beforeend", "<form><input aria-labelledby=a></form><span id=b>Verification code</span>")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            **({'parent': nested.parent} if explicit_parent else {}))[0]
    try:
        leaf.evaluate('(revert)=>{const e=document.querySelector("#b");e.id="a";if(revert)e.id="b"}', revert)
        if explicit_parent:
            with pytest.raises(ValueError):
                codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        else:
            assert not codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


@pytest.mark.parametrize('explicit_parent', [False, True])
def test_combined_historical_id_links_are_sticky(nested, explicit_parent):
    origin, leaf = setup_chain(nested)
    if not explicit_parent:
        nested.page.goto(origin+'/leaf')
        leaf = nested.page
    leaf.evaluate('document.body.insertAdjacentHTML("beforeend", "<form><input id=other aria-labelledby=a></form><span id=b>Verification code</span>")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            **({'parent': nested.parent} if explicit_parent else {}))[0]
    try:
        leaf.evaluate('()=>{const e=document.querySelector("#b"),i=document.querySelector("#other");e.id="c";i.setAttribute("aria-labelledby","c");e.id="b";i.setAttribute("aria-labelledby","a")}')
        if explicit_parent:
            with pytest.raises(ValueError):
                codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        else:
            assert not codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


@pytest.mark.parametrize('explicit_parent', [False, True])
def test_historical_name_text_before_link_is_sticky(nested, explicit_parent):
    origin, leaf = setup_chain(nested)
    if not explicit_parent:
        nested.page.goto(origin+'/leaf')
        leaf = nested.page
    leaf.evaluate('document.body.insertAdjacentHTML("beforeend", "<form><input id=other aria-labelledby=a></form><span id=c>Address</span>")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            **({'parent': nested.parent} if explicit_parent else {}))[0]
    try:
        leaf.evaluate('()=>{const e=document.querySelector("#c"),i=document.querySelector("#other");e.textContent="Verification code";i.setAttribute("aria-labelledby","c");e.textContent="Address";i.setAttribute("aria-labelledby","a")}')
        if explicit_parent:
            with pytest.raises(ValueError):
                codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        else:
            assert not codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


@pytest.mark.parametrize('text', ['Address', 'Decoration'])
def test_unrelated_name_id_link_does_not_refuse(nested, text):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(text)=>{document.body.insertAdjacentHTML("beforeend", "<form><input aria-labelledby=a></form><span id=b></span>");document.querySelector("#b").textContent=text}', text)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate('document.querySelector("#b").id="a"')
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('document.querySelector("form input").value==="Q!7&z=R9"')
    finally:
        codes.release(target)
