import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes

@pytest.mark.parametrize('duplicate', [False, True])
def test_nested_closed_roots_selector_identity(nested, duplicate):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(duplicate)=>{document.querySelector("form").remove();const a=document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"});const b=a.appendChild(document.createElement("div")).attachShadow({mode:"closed"});b.innerHTML="<form><input id=challenge autocomplete=one-time-code></form>";window.fixtureRoot=b;if(duplicate){const r=document.body.appendChild(document.createElement("div")).attachShadow({mode:"closed"});r.innerHTML="<input id=challenge hidden>"}}', duplicate)
    if duplicate:
        with pytest.raises(ValueError, match='ambiguous code selector'):
            codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')
        assert leaf.evaluate('window.fixtureRoot.querySelector("input").value===""')
        return
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, field_selector='#challenge')[0]
    try:
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic()+20)
        assert leaf.evaluate('window.fixtureRoot.querySelector("input").value==="Q!7&z=R9"')
    finally:
        codes.release(target)
