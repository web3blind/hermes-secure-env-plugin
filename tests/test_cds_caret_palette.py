"""Actual public CDS caret palette on unchanged synthetic OTP receivers."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope

def install_cds_caret_palette(leaf, palette='var'):
    leaf.add_style_tag(content=':root{--color-fg:#0a0b0d;--color-fgPrimary:#0052ff}')
    leaf.evaluate('''palette=>{
      window.reconcileCell=(e,active)=>{
        e.style.caretColor=palette==='var'?(active?'var(--color-fgPrimary)':'var(--color-fg)'):
          (active?'rgb(0, 82, 255)':'rgb(10, 11, 13)');
        wt(e,undefined,undefined,undefined,undefined,undefined,'text',e.name);
      };
      for(const e of originalCells)reconcileCell(e,document.activeElement===e);
      originalCells[0].focus();
    }''',palette)

@pytest.mark.parametrize('paint',[False,True])
@pytest.mark.parametrize('palette',['var','rgb'])
def test_public_cds_caret_palette_preserves_retained_cells(nested,paint,palette):
    origin,leaf=setup_chain(nested)
    prepare(leaf,paint=paint)
    install_cds_caret_palette(leaf,palette)
    target=codes.discover(origin,'Synthetic public CDS caret colors',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        with fill_diagnostic_scope() as diag:
            result=codes.fill(target,'123456',time.monotonic()+60)
        assert result is True,diag
        assert leaf.evaluate("originalCells.every((e,i)=>e===document.querySelector('[name=code'+i+']')&&e.value===String(i+1)&&!e.hasAttribute('value'))")
    finally:
        codes.release(target)
