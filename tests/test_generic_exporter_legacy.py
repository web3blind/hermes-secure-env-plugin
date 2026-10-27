"""Nonmutating exporter preserves legacy control indices and adapters."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


@pytest.mark.parametrize('decoration', ['<textarea aria-label="Notes"></textarea>', '<div contenteditable="plaintext-only" aria-label="Notes"></div>'])
def test_legacy_split_ignores_noninput_indices(nested, decoration):
    origin, leaf = setup_chain(nested)
    field = '<input autocomplete="one-time-code" maxlength="1">'
    leaf.evaluate('(html)=>document.body.innerHTML=html', '<form>'+decoration.join([field]*6)+'</form>')
    before = leaf.evaluate('document.body.innerHTML')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        assert leaf.evaluate('document.body.innerHTML') == before
        assert len(target.controls) == 6
        assert codes.fill(target, 'A!2#3$', time.monotonic()+30)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value).join("")') == 'A!2#3$'
    finally:
        codes.release(target)
