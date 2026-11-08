"""Indexed, form-less code controls: disposable Chromium, synthetic values only."""
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def markup(n=6, form=False):
    digits = ''.join(f'<input type="text" name="code-{i}" inputmode="numeric" pattern="[0-9]" autocomplete="off">' for i in range(n))
    body = '<section><h2>Enter confirmation code</h2><div><div><div>' + digits + '</div></div></div></section>'
    return '<form>' + body + '</form>' if form else body


def handler(leaf):
    leaf.evaluate('''()=>{const digits=Array.from(document.querySelectorAll('input'));window.fixtureState=[];window.fixtureSubmitted=0;
      digits.forEach((e,i)=>e.addEventListener('input',()=>{
        fixtureState[i]=e.value;
        if(i+1<digits.length)digits[i+1].focus();
        if(fixtureState.filter(Boolean).length===digits.length)fixtureSubmitted++;
      }));}''')


@pytest.mark.parametrize('n',range(4,17))
@pytest.mark.parametrize('form',[False,True])
def test_indexed_fill(nested,n,form):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',markup(n,form))
    handler(leaf)
    targets=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)
    assert len(targets)==1
    target=targets[0]
    try:
        assert len(target.controls)==n
        assert codes.fill(target,'1'*n,time.monotonic()+60)
        assert leaf.evaluate('(n)=>fixtureState.length===n && fixtureState.every(v=>v==="1") && fixtureSubmitted===1',n)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.maxLength===-1)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack',[
    'document.querySelector("input").name="code-1"',
    'document.querySelector("input").name="account-0"',
    'document.querySelector("input").pattern="[0-9]+"',
    'document.querySelector("input").removeAttribute("inputmode")',
    'document.querySelector("input").setAttribute("maxlength","8")',
    'document.querySelector("input").name="promo-code-0"',
    'document.querySelector("input").name="code-00"',
    'document.querySelectorAll("input")[5].name="code-6"',
    'document.querySelector("input").parentElement.append(document.querySelector("input"))',
    'document.querySelector("input").parentElement.setAttribute("aria-label","Payment card")',
    'document.querySelector("input").parentElement.setAttribute("aria-label","Password recovery")',
    'document.querySelector("input").type="password"',
    'document.querySelector("input").parentElement.removeChild(document.querySelectorAll("input")[2])',
    'document.querySelectorAll("input")[5].removeAttribute("pattern")',
    'const f=document.body.appendChild(document.createElement("form"));f.id="other";document.querySelector("input").setAttribute("form","other")',
])
def test_indexed_invalid(nested,attack):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',markup())
    leaf.evaluate(attack)
    assert codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)==[]






def completion(leaf):
    assert leaf.evaluate('fixtureState.join("")==="123456" && fixtureSubmitted===1')




def test_indexed_registered_https(nested,tmp_path,monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested,('parent.test','parent.test'),True,tmp_path,monkeypatch,
        markup=markup(),setup_hook=handler,synthetic_code='123456',completion_check=completion)
