"""Original visible opacity and per-cell wrapper topology."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


@pytest.mark.parametrize('shape', ['opacity', 'nested_wrappers'])
def test_original_visible_geometry_and_nested_cell_focus(nested, shape):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.evaluate('''shape => {
      for (const e of originalCells) {
        if (shape === 'opacity') e.style.opacity = '0.88';
        if (shape === 'nested_wrappers') {
          const span = e.parentElement, wrapper = document.createElement('div');
          wrapper.style.display = 'inline-block';
          span.before(wrapper); wrapper.append(span);
        }
      }
      originalCells[0].focus();
    }''', shape)
    target = codes.discover(origin, 'Synthetic original visible code cells', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        with fill_diagnostic_scope() as diagnostic:
            assert codes.fill(target, '123456', time.monotonic() + 60) is True, diagnostic
        assert leaf.evaluate("originalCells.map(e => e.value).join('')") == '123456'
        assert leaf.evaluate("originalCells.every(e => e.name.startsWith('code') && e.type === 'text')")
        if shape == 'opacity':
            assert leaf.evaluate("originalCells.every(e => getComputedStyle(e).opacity === '0.88')")
    finally:
        codes.release(target)
