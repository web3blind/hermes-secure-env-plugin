"""Metadata-only caret witnesses retain reverted DOM stylesheet history."""
import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from secure_env_ingress.nested_code import _GUARD

@pytest.mark.parametrize('view',['inspection','frame_owner'])
@pytest.mark.parametrize('change',['style','link','nested_style','decoration'])
def test_metadata_caret_stylesheet_history(nested,view,change):
    _,leaf=setup_chain(nested)
    prepare(leaf,paint=False)
    install_cds_caret_palette(leaf)
    leaf.evaluate("const f=document.createElement('iframe');f.hidden=true;document.body.append(f)")
    expression='''({view,change})=>{
      const make=GUARD,ns=view==='inspection'?[...document.querySelectorAll('input')]:[document.querySelector('iframe')];
      const g=make(ns,true,[document],null,null,true);
      const initially=g.valid();
      let n;
      if(change==='link'){n=document.createElement('link');n.rel='stylesheet'}
      else if(change==='nested_style'){n=document.createElement('div');n.innerHTML='<style>input[style*="--color-fgPrimary"]{opacity:0}</style>'}
      else if(change==='decoration'){n=document.createElement('span');n.textContent='ordinary decoration'}
      else{n=document.createElement('style');n.textContent='input[style*="--color-fgPrimary"]{opacity:0}'}
      document.body.append(n);
      const e=originalCells[0],before=e.getAttribute('style');
      e.style.caretColor='var(--color-fg)';e.setAttribute('style',before);n.remove();
      const after=g.valid();g.close();return {initially,after};
    }'''.replace('GUARD',_GUARD)
    result=leaf.evaluate(expression,dict(view=view,change=change))
    assert result['initially'] is True
    assert result['after'] is (change=='decoration'),result
