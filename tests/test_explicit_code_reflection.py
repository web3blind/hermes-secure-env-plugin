"""Controlled numeric cells reflect their own value without becoming new targets."""
from pathlib import Path
import time

import pytest

from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes


def descriptor(layout='indexed_cells'):
    result = dict(version=1, purpose='transient_code',
                  validation=dict(charset='ascii_digits', exact_length=5, multiline=False),
                  layout=layout)
    if layout == 'indexed_cells':
        result.update(group='#numeric-group', field_selector='input', order='dom', expected_count=5)
    else:
        result['fields'] = [dict(selector=f'#cell-{i}') for i in range(5)]
    return result


def prepare(leaf, attack='', service=False):
    root = Path(__file__).with_name('fixtures')
    # Fixed test-only markup; no page/user content is interpolated.
    leaf.evaluate('document.body.innerHTML=\'<div id="fixture-mount"></div>\'')
    for name in ('react-18.3.1.production.min.js', 'react-dom-18.3.1.production.min.js'):
        leaf.add_script_tag(content=(root / name).read_text())
    leaf.evaluate('''attack => {
      window.fixtureAttack=attack;
      function Code(){
        const [value,setValue]=React.useState(['','','','','']);
        return React.createElement('form',{onSubmit:e=>e.preventDefault()},
          React.createElement('div',{id:'numeric-group'},value.map((v,i)=>
            React.createElement('div',{key:i},React.createElement('input',{
              id:'cell-'+i,type:'text',inputMode:'numeric',autoComplete:i===0?'one-time-code':'off',value:v,
              onChange:e=>{const next=value.slice();next[i]=e.target.value;
                ReactDOM.flushSync(()=>setValue(next));
                document.querySelector('#cell-'+Math.min(i+1,4)).focus();
                if(i===0&&window.fixtureAttack)Function(window.fixtureAttack)();}
            })))));
      }
      ReactDOM.createRoot(document.querySelector('#fixture-mount')).render(React.createElement(Code));
    }''', attack)
    leaf.wait_for_selector('#cell-4')
    leaf.evaluate('window.originalCells=Array.from(document.querySelectorAll("input"))')
    if service:
        leaf.evaluate('''()=>new Promise(resolve=>{
          const frame=document.createElement('iframe');
          frame.id='service-frame';frame.onload=()=>resolve();
          frame.src=new URL('/service',location.href).href;document.body.append(frame);
        })''')


@pytest.mark.parametrize('service', [False, True])
@pytest.mark.parametrize('layout', ['indexed_cells', 'ordered_cells'])
def test_controlled_explicit_cells(nested, layout, service):
    origin, leaf = setup_chain(nested)
    prepare(leaf, service=service)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, target_spec=descriptor(layout))[0]
    try:
        assert codes.fill(target, '12345', time.monotonic()+45)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input"),e=>e.value).join("")==="12345"')
        assert leaf.evaluate('originalCells.every((e,i)=>e===document.querySelectorAll("input")[i]&&e.maxLength===-1)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('service', [False, True])
@pytest.mark.parametrize('attack', [
    "const e=document.querySelector('#cell-0');e.setAttribute('value','x');e.setAttribute('value',e.value)",
    "document.querySelector('#cell-1').setAttribute('value','x')",
    "document.querySelector('#cell-0').setAttribute('title','changed')",
    "const e=document.querySelector('#cell-0');e.setAttribute('title','changed');e.removeAttribute('title')",
    "const e=document.querySelector('#cell-1');e.replaceWith(e.cloneNode(true))",
    "document.querySelector('form').setAttribute('action','/other')",
])
def test_reflection_does_not_acknowledge_other_history(nested, attack, service):
    origin, leaf = setup_chain(nested)
    prepare(leaf, attack, service=service)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, target_spec=descriptor())[0]
    try:
        from secure_env_ingress.bound_cdp import fill_diagnostic_scope
        with fill_diagnostic_scope() as evidence:
            try:
                assert not codes.fill(target, '12345', time.monotonic()+45)
            except ValueError:
                pass
        assert evidence['writes_attempted'] == 1
        # The attack itself may change the second input's value property.
        # No subsequent code setter may reach the untouched remaining inputs.
        assert leaf.evaluate('originalCells.slice(2).every(e=>e.value==="")')
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack', [
    "const f=document.querySelector('#service-frame');f.setAttribute('title','changed');f.removeAttribute('title')",
    "const f=document.querySelector('#service-frame');f.replaceWith(f.cloneNode(true))",
    "document.querySelector('#service-frame').setAttribute('src','https://other.test/service')",
])
def test_service_frame_authority_still_refuses(nested, attack):
    origin, leaf = setup_chain(nested)
    prepare(leaf, attack, service=True)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id,
                            parent=nested.parent, target_spec=descriptor())[0]
    try:
        try:
            assert not codes.fill(target, '12345', time.monotonic()+45)
        except ValueError:
            pass
        assert leaf.evaluate('originalCells.slice(1).every(e=>e.value==="")')
    finally:
        codes.release(target)


def test_registered_controlled_cells_https(nested, tmp_path, monkeypatch):
    import asyncio
    import json
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime, post
    from test_tool_https_e2e import running_gateway_loop
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry
    from secure_env_ingress import runtime as runtime_module

    origin, leaf = setup_chain(nested)
    prepare(leaf, service=True)
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    factory = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime',
                        lambda cfg, h, token: factory(cfg, h, token, trust_roots=root))
    pending = []
    async def submit(content):
        token = urlsplit(content.split('form: ', 1)[1].split(' for ', 1)[0]).fragment
        status, form = await asyncio.to_thread(post, settings, root, '/session',
                                              {'token': token, 'initData': ''})
        assert status == 200 and form['target']['confirmation_required'] is True
        status, body = await asyncio.to_thread(post, settings, root, '/submit',
            {'token': token, 'initData': '', 'values': ['12345'], 'confirmed': True}, timeout=90)
        assert (status, body) == (200, {'filled': True})
    async def send(chat_id, content, metadata=None):
        assert chat_id == '-600'
        pending.append(asyncio.create_task(submit(content)))
        return SimpleNamespace(success=True)
    async def drain():
        await asyncio.gather(*pending)
    with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM: SimpleNamespace(send=send)}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM,
            user_id='7', chat_id='-600', chat_type='group'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600',
            chat_type='group', session_id=nested.sup.task_id, session_key='key', cron_session='')
        try:
            raw = registry.dispatch('secure_env_vault', {'origin': origin, 'label': 'Synthetic',
                'mode': 'code', 'parent': nested.parent, 'target_spec': descriptor()},
                task_id=nested.sup.task_id, session_id=nested.sup.task_id)
        finally:
            sc.clear_session_vars(tokens)
        asyncio.run_coroutine_threadsafe(drain(), loop).result(timeout=100)
    assert json.loads(raw)['status'] == 'filled' and '12345' not in raw
    assert leaf.evaluate('originalCells.map(e=>e.value).join("")==="12345"')
    assert leaf.evaluate('originalCells.every((e,i)=>e===document.querySelectorAll("input")[i])')
    assert not (home / '.env').exists() and not (home / 'vault').exists()
