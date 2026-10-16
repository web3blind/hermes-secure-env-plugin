"""Exact indexed membership and sticky callback guards, including 100 cells."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('attack', [
    'const g=document.querySelector("#group"),e=g.querySelector("input");g.append(e)',
    'const g=document.querySelector("#group"),e=g.querySelector("input");g.append(e);g.prepend(e)',
    'const e=document.querySelector("input");e.remove()',
    'const g=document.querySelector("#group");g.append(document.createElement("input"));g.lastChild.remove()',
    'document.querySelector("#group").id="other";document.querySelector("#other").id="group"',
])
@pytest.mark.parametrize('n', [2, 100])
def test_index_membership_history(nested, attack, n):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(n)=>document.body.innerHTML="<div id=group>"+"<input maxlength=1>".repeat(n)+"</div>"', n)
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(n, 'indexed_cells'))[0]
    try:
        leaf.evaluate('()=>{'+attack+'}')
        with pytest.raises(ValueError):
            codes.fill(t, '!'*n, time.monotonic()+120)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    finally:
        codes.release(t)



@pytest.mark.parametrize('index', [0, 49, 99])
def test_100_transient_cell_mutation_before_write(nested, index):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+"<input maxlength=1>".repeat(100)+"</div>"')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(100, 'indexed_cells'))[0]
    try:
        leaf.evaluate('(i)=>{const e=document.querySelectorAll("input")[i];e.maxLength=2;e.maxLength=1}', index)
        with pytest.raises(ValueError):
            codes.fill(t, '!'*100, time.monotonic()+120)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    finally:
        codes.release(t)



def test_100_callback_after_50_stops_next_write(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+"<input maxlength=1>".repeat(100)+"</div>"')
    leaf.evaluate('document.querySelectorAll("input")[49].addEventListener("input",()=>{const e=document.querySelectorAll("input")[99];e.maxLength=2;e.maxLength=1},{once:true})')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(100, 'indexed_cells'))[0]
    try:
        try:
            assert not codes.fill(t, '!'*100, time.monotonic()+120)
        except ValueError:
            pass
        values = leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value)')
        assert values == ['!']*50+['']*50
    finally:
        codes.release(t)



def test_callback_focus_next_retained_only(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group><input maxlength=1><input maxlength=1></div>"')
    leaf.evaluate('document.querySelector("input").addEventListener("input",()=>document.querySelectorAll("input")[1].focus())')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(2, 'indexed_cells'))[0]
    try:
        assert codes.fill(t, '!?', time.monotonic()+30)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value).join("")') == '!?'
    finally:
        codes.release(t)

