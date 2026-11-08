"""Synthetic uncontrolled cells and public submit-state transition; no accounts."""
from pathlib import Path
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


def prepare(leaf, wrapper_tag="div"):
    root=Path(__file__).with_name('fixtures')
    leaf.evaluate("document.body.innerHTML='<div id=mount></div>'")
    for name in ['react-18.3.1.production.min.js','react-dom-18.3.1.production.min.js']:
        leaf.add_script_tag(content=(root/name).read_text())
    leaf.evaluate('''(wrapperTag)=>{
      function App(){
        const [code,setCode]=React.useState(Array(6).fill(''));
        const [touched,setTouched]=React.useState(false);
        const refs=React.useRef([]);
        const fields=code.map((v,i)=>React.createElement(wrapperTag,{key:i},
          React.createElement('input',{
            name:'code'+i,type:'text',autoComplete:'one-time-code',
            ref:e=>refs.current[i]=e,
            onChange:event=>{
              const value=event.target.value;
              setCode(previous=>previous.map((old,j)=>j===i?value:old));
              setTouched(true);
              if(i<5)refs.current[i+1].focus();
            }
          })));
        return React.createElement(React.Fragment,null,
          React.createElement('form',null,...fields),
          React.createElement('button',{id:'submit',type:'button',disabled:touched&&code.some(v=>!v)},'Continue'));
      }
      ReactDOM.createRoot(document.querySelector('#mount')).render(React.createElement(App));
    }''', wrapper_tag)
    leaf.wait_for_selector('input[name=code5]')
    assert leaf.evaluate("[...document.querySelectorAll('input')].every(e=>!e.hasAttribute('value'))")
    assert leaf.evaluate("!document.querySelector('#submit').disabled")


def spec():
    return {'version':1,'purpose':'transient_code','layout':'ordered_cells',
            'validation':{'charset':'ascii_digits','exact_length':6,'multiline':False},
            'fields':[{'selector':f'input[name="code{i}"]'} for i in range(6)]}


def test_native_uncontrolled_cells_allow_submit_validation_state(nested):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    target=codes.discover(origin,'Synthetic submit state',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        with fill_diagnostic_scope() as diagnostic:
            result=codes.fill(target,'123456',time.monotonic()+30)
        assert result is True, diagnostic
        assert leaf.evaluate("[...document.querySelectorAll('input')].map(e=>e.value).join('')")=='123456'
        assert leaf.evaluate("!document.querySelector('#submit').disabled")
        assert leaf.evaluate("[...document.querySelectorAll('input')].every(e=>!e.hasAttribute('value'))")
    finally:
        codes.release(target)
