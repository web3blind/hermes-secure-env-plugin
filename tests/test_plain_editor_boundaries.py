"""Editing attributes cannot turn fallback pixels/widgets into text fields."""
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from exact_card_helpers import page, registered_fill
from secure_env_ingress import code_targets as codes

KINDS = ['canvas', 'img', 'iframe', 'button', 'role-button', 'own-open', 'own-closed']
JS = '''([id,kind,editing])=>{let e=document.querySelector('#'+id);
 if(['canvas','img','iframe','button'].includes(kind)){
  const n=document.createElement(kind);n.id=id;n.setAttribute('contenteditable',editing);n.tabIndex=0;e.replaceWith(n);e=n;
 }
 if(kind==='role-button')e.setAttribute('role','button');
 if(kind.startsWith('own-'))e.attachShadow({mode:kind.slice(4)}).innerHTML='<span>Rich surface</span>';
}'''


@pytest.mark.parametrize('editing', ['true', 'plaintext-only'])
@pytest.mark.parametrize('kind', KINDS)
def test_code_non_text_host_before_prompt(nested, kind, editing):
    origin, leaf=setup_chain(nested)
    leaf.evaluate('s=>document.body.innerHTML=`<div id=challenge contenteditable="${s}"></div>`',editing)
    leaf.evaluate(JS,['challenge',kind,editing])
    with pytest.raises(ValueError):
        codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent,target_spec=spec())


@pytest.mark.parametrize('kind', KINDS)
def test_card_non_text_host_before_approval(nested, tmp_path, monkeypatch, kind):
    origin, leaf, target=page(nested,kind='editable')
    leaf.evaluate(JS,['pan',kind,'true'])
    result, seen, resolved=registered_fill(nested,tmp_path,monkeypatch,origin,target)
    assert result['status']=='target_refused',result
    assert not seen and not resolved
    assert leaf.evaluate('window.writes===0&&!window.clicked&&!window.submitted')
