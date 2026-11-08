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
    before = leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>Array.from(e.attributes).filter(a=>a.name!=="data-hermes-vault-slot").map(a=>[a.name,a.value]))')
    value = ''.join(str(i % 10) for i in range(count))
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(count, layout))[0]
    try:
        assert codes.fill(target, value, time.monotonic()+240)
        actual = leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value)')
        assert actual == list(value if layout == 'indexed_cells' else value[::-1])
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>Array.from(e.attributes).filter(a=>a.name!=="data-hermes-vault-slot").map(a=>[a.name,a.value]))') == before
    finally:
        codes.release(target)
