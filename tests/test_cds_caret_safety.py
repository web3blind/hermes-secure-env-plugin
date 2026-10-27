"""Color-valued caret acknowledgement must not hide other style history."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope

@pytest.mark.parametrize('paint',[False,True])
@pytest.mark.parametrize('attack',['opacity','display','font','priority','custom_case','invalid_caret'])
def test_caret_palette_retains_noncaret_refusals(nested,paint,attack):
    origin,leaf=setup_chain(nested)
    prepare(leaf,paint=paint)
    install_cds_caret_palette(leaf)
    leaf.evaluate("originalCells[0].style.setProperty('--Guard','1')")
    target=codes.discover(origin,'Synthetic caret palette refusal',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        leaf.evaluate('''attack=>{
          const e=originalCells[0],before=e.getAttribute('style');
          if(attack==='opacity')e.style.opacity='0';
          if(attack==='display')e.style.display='none';
          if(attack==='font')e.style.fontWeight='200';
          if(attack==='priority')e.style.setProperty('caret-color','var(--color-fgPrimary)','important');
          if(attack==='custom_case')e.setAttribute('style',before.replace('--Guard:','--guard:'));
          if(attack==='invalid_caret')e.setAttribute('style',before.replace(/caret-color:[^;]+/,'caret-color: url(about:blank)'));
          e.setAttribute('style',before);
        }''',attack)
        with fill_diagnostic_scope() as diag:
            try:
                result=codes.fill(target,'123456',time.monotonic()+60)
            except ValueError as exc:
                assert str(exc)=='code document changed'
                result=False
        assert result is False,diag
        assert diag.get('writes_attempted',0)==0,diag
        assert leaf.evaluate("originalCells.every(e=>e.value==='')")
    finally:
        codes.release(target)
