"""Head-ancestor labelledby history must be learned before title filtering."""
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress.nested_code import _GUARD


@pytest.mark.parametrize('method',['replace','character'])
def test_transient_head_source_keeps_title_text_history(nested,method):
    _,leaf=setup_chain(nested)
    leaf.set_content('<html><head id="heading"><title>Wallet</title></head><body><input id="selected" name="code" maxlength="6"><input id="other"></body></html>')
    before=leaf.evaluate('''source=>{
      const factory=(0,eval)('('+source+')');
      window.inspector=factory([document.getElementById('selected')],true);
      return inspector.valid();
    }''',_GUARD)
    assert before is True
    try:
        after=leaf.evaluate('''method=>{
          const other=document.getElementById('other');
          other.setAttribute('aria-labelledby','heading');
          if(method==='replace'){document.title='Code';document.title='Wallet'}
          else{document.querySelector('title').firstChild.data='Code';document.querySelector('title').firstChild.data='Wallet'}
          other.removeAttribute('aria-labelledby');
          return inspector.valid();
        }''',method)
        assert after is False
    finally:
        leaf.evaluate('inspector.close();delete window.inspector')
