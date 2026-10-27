"""Caret acknowledgement must preserve CSS case and declaration history."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


@pytest.mark.parametrize('paint', [False, True])
@pytest.mark.parametrize('attack', ['case', 'case_restore', 'order'])
def test_noncaret_css_case_and_order_history_refuses(nested, paint, attack):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=paint)
    leaf.evaluate("originalCells[0].style.cssText += '; --Gate: 1; opacity: var(--Gate, 0)'")
    target = codes.discover(origin, 'Synthetic CSS history refusal', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate('''attack => {
          const e = originalCells[0], before = e.getAttribute('style');
          if (attack === 'order') {
            const parts = before.split(';').map(s => s.trim()).filter(Boolean);
            e.setAttribute('style', parts.reverse().join(';'));
          } else {
            e.setAttribute('style', before.replace('--Gate:', '--gate:'));
            if (attack === 'case_restore') e.setAttribute('style', before);
          }
        }''', attack)
        with fill_diagnostic_scope() as diagnostic:
            try:
                refused = codes.fill(target, '123456', time.monotonic() + 60) is False
            except ValueError as exc:
                assert str(exc) == 'code document changed'
                refused = True
            assert refused
        assert diagnostic.get('writes_attempted', 0) == 0, diagnostic
        assert leaf.evaluate("originalCells.every(e => e.value === '')")
    finally:
        codes.release(target)


@pytest.mark.parametrize('paint', [False, True])
def test_unchanged_case_sensitive_custom_property_allows_caret(nested, paint):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=paint)
    leaf.evaluate("originalCells.forEach(e => e.style.cssText += '; --Gate: 1; opacity: var(--Gate, 0)')")
    target = codes.discover(origin, 'Synthetic unchanged CSS property', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        with fill_diagnostic_scope() as diagnostic:
            assert codes.fill(target, '123456', time.monotonic() + 60) is True, diagnostic
        assert leaf.evaluate("originalCells.map(e => e.value).join('')") == '123456'
    finally:
        codes.release(target)
