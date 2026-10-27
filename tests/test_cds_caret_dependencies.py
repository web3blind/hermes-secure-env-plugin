"""Caret syntax alone must not authorize CSS-dependent effects."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from test_exact_submit_state import spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope

@pytest.mark.parametrize('paint',[False,True])
@pytest.mark.parametrize('attack',['input_selector','label_selector','escaped_selector','missing_var','noncolor_var','fallback'])
def test_caret_dependency_history_refuses(nested,paint,attack):
    origin,leaf=setup_chain(nested)
    prepare(leaf,paint=paint)
    install_cds_caret_palette(leaf)
    if attack=='input_selector':
        leaf.add_style_tag(content='input[name="code0"][style*="--color-fg)"]{opacity:0}')
    if attack=='label_selector':
        leaf.evaluate("document.body.insertAdjacentHTML('beforeend','<span id=purpose>Verification code</span>');originalCells[0].setAttribute('aria-labelledby','purpose')")
        leaf.add_style_tag(content='body:has(input[name="code0"][style*="--color-fg)"]) #purpose{display:none}')
    if attack=='escaped_selector':
        leaf.add_style_tag(content=r'input[name="code0"][st\79 le*="--color-fg)"]{opacity:0}')
    if attack=='noncolor_var':
        leaf.evaluate("originalCells[0].style.setProperty('--bad-caret','12px')")
    target=codes.discover(origin,'Synthetic caret dependency boundary',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        leaf.evaluate('''attack=>{
          const e=originalCells[0],before=e.getAttribute('style');
          e.style.caretColor=attack==='missing_var'?'var(--missing-caret)':attack==='noncolor_var'?'var(--bad-caret)':attack==='fallback'?'var(--missing-caret, red)':'var(--color-fg)';
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
