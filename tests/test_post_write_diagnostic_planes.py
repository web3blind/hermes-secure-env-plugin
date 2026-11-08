"""Native Vault does not gate writes on post-input presentation or focus."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_submit_state import prepare, spec
from secure_env_ingress import code_targets as codes, nested_code as nc
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


@pytest.mark.parametrize('change',['label','blur','document-focus'])
def test_native_post_write_presentation_is_not_a_lock(nested,change,caplog):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    target=codes.discover(origin,'Synthetic code',nested.sup.task_id,parent=nested.parent,target_spec=spec())[0]
    try:
        if change=='label':
            leaf.evaluate("document.querySelector('input').addEventListener('input',e=>e.target.setAttribute('aria-label','Updated UI'),{once:true})")
        elif change=='blur':
            leaf.evaluate("window.addEventListener('change',()=>document.activeElement.blur(),{once:true})")
        else:
            nc._invoke(target.supervisor,target.leaf_sid,target.leaf_guard,'function(){Document.prototype.hasFocus=()=>false;return true}')
        with fill_diagnostic_scope() as diag:
            result=codes.fill(target,'654321',time.monotonic()+60)
        assert result is True
        assert diag['writes_attempted']==diag['writes_confirmed']==6
        assert '654321' not in caplog.text
        assert leaf.evaluate("[...document.querySelectorAll('input')].map(e=>e.value).join('')")=='654321'
    finally:codes.release(target)
