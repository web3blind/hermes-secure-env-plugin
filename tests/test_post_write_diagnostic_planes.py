"""Separate post-write safety, document focus and expected-control failures."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes, nested_code as nc
from secure_env_ingress.bound_cdp import fill_diagnostic_scope,log_fill_diagnostic


@pytest.mark.parametrize('failure,reason',[
    ('guard','guard_refused'),
    ('document','document_focus_lost'),
    ('target','unexpected_focus'),
])
def test_post_write_fixed_diagnostic_does_not_retry(nested,failure,reason,caplog):
    origin,leaf=setup_chain(nested)
    prepare(leaf,paint=True)
    target=codes.discover(origin,'Synthetic write boundary',nested.sup.task_id,parent=nested.parent,target_spec=spec())[0]
    try:
        if failure=='guard':
            leaf.evaluate("originalCells[0].addEventListener('input',()=>originalCells[0].setAttribute('aria-label','Changed authority'),{once:true})")
        elif failure=='target':
            leaf.evaluate("window.addEventListener('change',()=>document.activeElement.blur(),{once:true})")
        else:
            nc._invoke(target.supervisor,target.leaf_sid,target.leaf_guard,
                'function(){const original=Document.prototype.hasFocus;let calls=0;Document.prototype.hasFocus=function(){return ++calls<3&&original.call(this)};return true}')
        with fill_diagnostic_scope() as diag:
            result=codes.fill(target,'654321',time.monotonic()+60)
            log_fill_diagnostic(diag)
        assert result is False
        assert diag['stage']=='readback'
        assert diag['reason']==reason,diag
        assert diag['writes_attempted']==1 and diag['writes_confirmed']==1
        assert '654321' not in caplog.text
        assert leaf.evaluate("originalCells.slice(1).every(e=>e.value==='')")
        checks=nc._invoke(target.supervisor,target.leaf_sid,target.leaf_guard,'function(){return this.lastWriteChecks()}')['value']
        assert set(checks)=={'guard','documentFocus','targetFocus'}
        assert all(type(value) is bool for value in checks.values())
        assert checks[{'guard':'guard','document':'documentFocus','target':'targetFocus'}[failure]] is False
    finally:
        codes.release(target)
