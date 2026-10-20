"""Post-dispatch failure planes retain refusal and exact write counters."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope

@pytest.mark.parametrize('effect', ['unchanged', 'old_email_attribute', 'one_disabled', 'duplicate_disabled', 'focus_button'])
def test_first_write_cause_matrix(nested, effect, pytestconfig):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    leaf.evaluate('''()=>{
      const old=document.createElement('form');old.hidden=true;
      old.innerHTML='<input type="email" name="old-email"><button type="button">Continue</button>';
      old.id='old-email-form';document.body.append(old);
      const b=document.createElement('button');b.id='foreign-focus';b.textContent='Focus target';document.body.append(b);
    }''')
    target=codes.discover(origin,'Synthetic hidden-email readback matrix',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        leaf.evaluate('''effect=>{
          originalCells[0].addEventListener('input',()=>{
            const b=document.querySelector('#submit');
            if(effect==='old_email_attribute')document.querySelector('#old-email-form input').setAttribute('aria-invalid','false');
            if(effect==='duplicate_disabled'){b.disabled=true;b.disabled=true}
          });
          if(effect==='focus_button'){
            const b=document.querySelector('#foreign-focus');
            originalCells[0].addEventListener('change',()=>b.focus());
          }
        }''',effect)
        with fill_diagnostic_scope() as diag:
            result=codes.fill(target,'123456',time.monotonic()+60)
        occupancy=leaf.evaluate('originalCells.map(e=>e.value.length>0)')
        pytestconfig.cache.set('senv_readback_matrix/'+effect,dict(diag,result=result,occupancy=occupancy))
        if effect in ('unchanged','one_disabled'):
            assert result is True,diag
            assert all(occupancy)
        else:
            assert result is False,diag
            expected_reason='unexpected_focus' if effect=='focus_button' else 'guard_refused'
            assert diag['stage']=='readback' and diag['reason']==expected_reason,diag
            assert diag['writes_attempted']==diag['writes_confirmed']==1,diag
            assert occupancy==[True,False,False,False,False,False]
    finally:
        codes.release(target)
