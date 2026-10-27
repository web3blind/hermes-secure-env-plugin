"""Combined exact-code/Privy boundary acceptance on synthetic Chromium."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('layout', ['ordered_cells', 'indexed_cells'])
@pytest.mark.parametrize('count', [6, 100])
def test_cells_without_maxlength(nested, layout, count):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(n)=>{document.body.innerHTML="<div id=group></div>";for(let i=0;i<n;i++){const e=document.createElement("input");e.id="c"+i;e.name="code-"+i;e.inputMode="numeric";e.pattern="[0-9]";e.autocomplete="off";document.querySelector("#group").append(e)}}', count)
    before = leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>Array.from(e.attributes,a=>[a.name,a.value]))')
    value = ''.join(str(i % 10) for i in range(count))
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(count, layout))[0]
    try:
        assert codes.fill(target, value, time.monotonic()+240)
        actual = leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value)')
        assert actual == list(value if layout == 'indexed_cells' else value[::-1])
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>Array.from(e.attributes,a=>[a.name,a.value]))') == before
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack', ['wrong_length', 'truncation', 'redirect', 'membership'])
def test_unbounded_cells_refuse_wrong_writes(nested, attack):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+Array.from({length:6},(_,i)=>"<input id=c"+i+">").join("")+"</div><input id=outside>"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(6, 'indexed_cells'))[0]
    try:
        if attack == 'truncation':
            leaf.evaluate('document.querySelector("#c0").addEventListener("input",e=>{e.target.value=""},{once:true})')
        elif attack == 'redirect':
            leaf.evaluate('document.querySelector("#c0").addEventListener("input",()=>document.querySelector("#outside").focus(),{once:true})')
        elif attack == 'membership':
            leaf.evaluate('document.querySelector("#group").append(document.createElement("input"))')
        try:
            assert not codes.fill(target, '12345' if attack == 'wrong_length' else '123456', time.monotonic()+30)
        except ValueError:
            pass
        assert leaf.evaluate('document.querySelector("#c1").value') == ''
        assert leaf.evaluate('document.querySelector("#outside").value') == ''
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.hasAttribute("maxlength"))')
    finally:
        codes.release(target)
