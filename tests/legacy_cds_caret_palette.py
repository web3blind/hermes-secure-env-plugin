"""Actual public CDS caret palette on unchanged synthetic OTP receivers."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from legacy_input_reconciliation import prepare
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
