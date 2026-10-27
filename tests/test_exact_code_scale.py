"""Bounded large exact targets; ordinary and adversarial 100-cell paths."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('n,layout', [(n, layout) for n in (1, 2, 3, 4, 16, 17, 32, 64, 99, 100) for layout in ('ordered_cells', 'indexed_cells')])
def test_exact_cells(nested, n, layout):
    origin, leaf = setup_chain(nested)
    markup = '<div id="group" style="direction:rtl">'+''.join(f'<div><input class=cell id="c{i}" maxlength="1"></div><span>decoration</span>' for i in range(n))+'<input class=unrelated></div>'
    leaf.evaluate('(s)=>document.body.innerHTML=s', markup)
    before = leaf.evaluate('document.body.innerHTML')
    exact = spec(n, layout)
    if layout == 'indexed_cells':
        exact['field_selector'] = 'input.cell'
    targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=exact)
    assert len(targets) == 1
    assert leaf.evaluate('document.body.innerHTML') == before
    t = targets[0]
    code = ''.join(chr(33+i%90) for i in range(n))
    start = time.monotonic()
    try:
        assert codes.fill(t, code, start+120)
        actual = leaf.evaluate('Array.from(document.querySelectorAll("input.cell"),e=>e.value).join("")')
        assert actual == (code[::-1] if layout == 'ordered_cells' else code)
        assert time.monotonic()-start < 120
    finally:
        codes.release(t)



@pytest.mark.parametrize('n', [1, 2, 4, 16, 17, 32, 64, 99, 100])
def test_exact_single_lengths(nested, n):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<input id=challenge>"')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(n))[0]
    try:
        value = '0'+'!'*(n-1)
        assert codes.fill(t, value, time.monotonic()+120)
        assert leaf.evaluate('document.querySelector("#challenge").value') == value
    finally:
        codes.release(t)






@pytest.mark.parametrize('value', ['!'*99, '!'*101])
def test_100_length_mismatch_no_writes(nested, value):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+"<input maxlength=1>".repeat(100)+"</div>"')
    t = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(100, 'indexed_cells'))[0]
    try:
        with pytest.raises(ValueError):
            codes.fill(t, value, time.monotonic()+120)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    finally:
        codes.release(t)










