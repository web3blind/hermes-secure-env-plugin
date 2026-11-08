"""Real public React input updater on synthetic numeric OTP cells."""
from pathlib import Path
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_submit_state import prepare as base_prepare, spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


def prepare(leaf, paint=False):
    base_prepare(leaf, wrapper_tag="span" if paint else "div")
    source=Path(__file__).with_name('fixtures')/'react-input-updater.js'
    leaf.add_script_tag(content=source.read_text())
    leaf.evaluate('''()=>{
      window.originalCells=[...document.querySelectorAll('input')];
      window.reconcileCell=(e,active)=>{
        e.style.caretColor=active?'auto':'transparent';
        wt(e,undefined,undefined,undefined,undefined,undefined,'text',e.name);
      };
      for(const e of originalCells){
        e.inputMode='numeric';e.pattern='[0-9]*';
        e.style.cssText='font: 16px Arial; width: 28px; height: 32px; padding: 2px; border: 1px solid gray; box-sizing: border-box; caret-color: transparent';
        e.addEventListener('focus',()=>reconcileCell(e,true));
        e.addEventListener('blur',()=>reconcileCell(e,false));
      }
    }''')
    if paint:
        leaf.add_style_tag(content=Path(__file__).with_name('fixtures').joinpath('layered-otp-paint.css').read_text())
        leaf.evaluate('''()=>{
          for(const e of originalCells){
            e.parentElement.className='cell-shell';
            e.parentElement.dataset.testid='cell-shell';
            e.parentElement.dataset.disabled='false';
            e.setAttribute('tabindex','0');
            e.parentElement.style.cssText='display: inline-block; border: 1px solid gray';
            e.addEventListener('focus',()=>e.parentElement.classList.add('fixture-focus'));
            e.addEventListener('blur',()=>e.parentElement.classList.remove('fixture-focus'));
            e.addEventListener('input',()=>{e.parentElement.classList.add('fixture-focus');reconcileCell(e,true)});
          }
          const find=rules=>{for(const r of rules){if(r.selectorText==='.fixture-focus')return r;
            if(r.cssRules){const found=find(r.cssRules);if(found)return found}}};
          window.fixturePaintRule=find(document.styleSheets[0].cssRules);
          originalCells[0].focus();
        }''')
















def assert_paint_refusal(nested, origin, leaf):
    try:
        target = codes.discover(origin, 'Synthetic unsupported paint', nested.sup.task_id,
                                parent=nested.parent, target_spec=spec())[0]
    except ValueError:
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
        return
    try:
        leaf.evaluate("originalCells[0].parentElement.classList.remove('fixture-focus')")
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)
