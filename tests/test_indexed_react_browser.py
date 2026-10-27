"""Actual public handler + controlled React inputs, synthetic account-free fixture."""
from pathlib import Path
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def prepare(leaf):
    root=Path(__file__).with_name('fixtures')
    leaf.evaluate('document.body.innerHTML=\'<div id="fixture-mount"></div>\'')
    for name in ['react-18.3.1.production.min.js','react-dom-18.3.1.production.min.js','privy-public-code-handler.js']:
        leaf.add_script_tag(content=(root/name).read_text())
    leaf.wait_for_selector('input[name=code-5]')
    leaf.evaluate('''()=>{window.fixtureFieldMetadata=Array.from(document.querySelectorAll("input"),e=>
      Array.from(e.attributes,a=>[a.name,a.value]).filter(a=>a[0]!=="value"));}''')


def complete(leaf):
    assert leaf.evaluate('fixtureComplete===true && fixtureSubmitted===1')
    assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.maxLength===-1)')
    assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value).join("")==="123456"')
    assert leaf.evaluate('''()=>JSON.stringify(Array.from(document.querySelectorAll("input"),e=>
      Array.from(e.attributes,a=>[a.name,a.value]).filter(a=>a[0]!=="value")))===JSON.stringify(fixtureFieldMetadata)'''), leaf.evaluate('({before:fixtureFieldMetadata,after:Array.from(document.querySelectorAll("input"),e=>Array.from(e.attributes,a=>[a.name,a.value]))})')


@pytest.mark.parametrize('selector',[None,'input[name="code-0"]'])
def test_public_react_handler(nested,selector):
    origin,leaf=setup_chain(nested)
    prepare(leaf)
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent,field_selector=selector)[0]
    try:
        assert codes.fill(target,'123456',time.monotonic()+60)
        complete(leaf)
    finally:
        codes.release(target)


@pytest.mark.parametrize('selector',[None,'input[name="code-0"]'])
def test_registered_react_https(nested,tmp_path,monkeypatch,selector):
    from test_nested_code import test_registered_nested_https as run
    run(nested,('parent.test','parent.test'),True,tmp_path,monkeypatch,
        markup='<div id="fixture-mount"></div>',setup_hook=prepare,synthetic_code='123456',completion_check=complete,field_selector=selector)
