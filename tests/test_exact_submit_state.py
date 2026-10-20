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


@pytest.mark.parametrize('attack',['complex_binding','button_label','nested_label','ancestor_button','button_state_roundtrip','button_replacement','button_reparent','multiple_buttons','button_class_history','credential_role','readonly','field_replacement','focus_exit','new_candidate'])
def test_submit_state_acknowledgement_preserves_refusals(nested,attack):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    target_spec=spec()
    if attack=='complex_binding':
        for field in target_spec['fields']:
            field['selector']='form '+field['selector']
    leaf.evaluate('''attack=>{
      const e=document.querySelector('input[name=code0]');
      const button=document.querySelector('#submit');
      if(attack==='button_label')e.setAttribute('aria-labelledby','submit');
      if(attack==='nested_label'){
        const label=document.createElement('div');label.id='source';button.before(label);label.append(button);
        e.setAttribute('aria-labelledby','source');
      }
      if(attack==='ancestor_button')button.append(document.querySelector('form'));
      if(attack==='multiple_buttons'){
        const extra=document.createElement('button');extra.id='extra';document.body.append(extra);
      }
      const foreign=document.createElement('input');foreign.id='foreign';document.body.append(foreign);
      e.addEventListener(attack==='focus_exit'?'change':'input',()=>{
        if(attack==='button_state_roundtrip'){button.disabled=true;button.disabled=false;}
        if(attack==='button_replacement')button.replaceWith(button.cloneNode(true));
        if(attack==='button_reparent'){
          const parent=button.parentElement;document.body.append(button);parent.append(button);
        }
        if(attack==='multiple_buttons')document.querySelector('#extra').disabled=true;
        if(attack==='button_class_history'){button.className='temporary';button.className='';}
        if(attack==='credential_role'){
          e.setAttribute('autocomplete','current-password');e.setAttribute('autocomplete','one-time-code');
        }
        if(attack==='readonly'){e.readOnly=true;e.readOnly=false;}
        if(attack==='field_replacement'){
          const other=document.querySelector('input[name=code1]');other.replaceWith(other.cloneNode());
        }
        if(attack==='focus_exit')foreign.focus();
        if(attack==='new_candidate'){
          const clone=e.cloneNode();document.body.append(clone);clone.remove();
        }
      },{once:true});
    }''',attack)
    target=codes.discover(origin,'Synthetic submit refusal',nested.sup.task_id,
                          parent=nested.parent,target_spec=target_spec)[0]
    try:
        try:
            result=codes.fill(target,'123456',time.monotonic()+30)
        except ValueError:
            result=False
        assert result is False
        assert leaf.evaluate("[...document.querySelectorAll('input[name^=code]')].slice(1).every(e=>!e.value)")
        assert leaf.evaluate("document.querySelector('#foreign').value===''")
    finally:
        codes.release(target)


def test_waiting_button_history_is_not_an_own_dispatch(nested):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    target=codes.discover(origin,'Synthetic waiting history',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        leaf.evaluate("const b=document.querySelector('#submit');b.disabled=true;b.disabled=false")
        with pytest.raises(ValueError):
            codes.fill(target,'123456',time.monotonic()+30)
        assert leaf.evaluate("[...document.querySelectorAll('input')].every(e=>!e.value)")
    finally:
        codes.release(target)
