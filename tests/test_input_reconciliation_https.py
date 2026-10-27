"""Public captured-CDP: registered exact-code delivery and guarded HTTPS fill."""
import asyncio
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_nested_code import nested as nested, setup_chain
from test_input_reconciliation import prepare
from test_cds_caret_palette import install_cds_caret_palette
from test_exact_submit_state import spec
from generic_helpers import registered
from test_runtime_e2e import make_runtime, post
from test_tool_https_e2e import running_gateway_loop


@pytest.mark.parametrize('case', [
    'react', 'button_pair', 'button_noop', 'title', 'hidden_srcdoc', 'hidden_blank',
    'clone', 'focus', 'history', 'title_source', 'canary_competing',
    'guard_diagnostic', 'focus_diagnostic',
])
def test_registered_compatibility_https(nested, tmp_path, monkeypatch, case):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry
    from secure_env_ingress import runtime as runtime_module, vault_ingress
    from secure_env_ingress.nested_code import _invoke
    from secure_env_ingress.bound_cdp import _fill_diagnostic

    origin, leaf = setup_chain(nested)
    if case == 'button_noop':
        from test_button_noop_history import prepare_noops
        prepare_noops(leaf)
    else:
        prepare(leaf, paint=True)
        install_cds_caret_palette(leaf)
    leaf.evaluate("document.title='Synthetic challenge'")
    if case in ('hidden_srcdoc', 'hidden_blank', 'canary_competing'):
        leaf.evaluate('''async blank=>{
          const f=document.createElement('iframe');f.style.display='none';
          if(blank)f.src='about:blank';else f.srcdoc='<div>Service</div>';
          await new Promise(resolve=>{f.onload=resolve;document.body.append(f)});
        }''', case == 'hidden_blank')
    if case == 'button_pair':
        leaf.evaluate('''()=>{
          const b=document.querySelector('button');b.setAttribute('data-disabled','false');
          for(const e of originalCells)e.addEventListener('change',()=>{
            b.setAttribute('data-disabled',String(b.disabled));
          });
        }''')
    if case == 'title':
        leaf.evaluate("originalCells[0].addEventListener('input',()=>{document.title='Synthetic challenge (1)'},{once:true})")
    if case == 'focus':
        leaf.evaluate("originalCells[0].addEventListener('change',()=>document.activeElement.blur(),{once:true})")
    if case == 'guard_diagnostic':
        leaf.evaluate("originalCells[0].addEventListener('input',()=>originalCells[0].setAttribute('aria-label','Changed'),{once:true})")

    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    factory = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', lambda cfg,h,token: factory(cfg,h,token,trust_roots=root))
    original_fill = vault_ingress.fill_verification_code
    diagnostics = []
    def fill(target, value, *, expires_at):
        scripts = {
            'clone': 'const e=this.document.querySelector("input");e.replaceWith(e.cloneNode())',
            'history': 'const e=this.document.querySelector("input"),n=e.name;e.name="password";e.name=n',
            'title_source': 'const d=this.document,t=d.head.querySelector("title"),e=d.querySelector("input");t.id="transient-title";e.setAttribute("aria-labelledby",t.id);d.title="Changed";t.removeAttribute("id");e.removeAttribute("aria-labelledby")',
            'canary_competing': 'const d=this.document.querySelector("iframe").contentDocument;for(let i=0;i<6;i++){const e=d.createElement("input");e.name="code"+i;d.body.append(e)}d.body.replaceChildren()',
            'focus_diagnostic': 'const original=Document.prototype.hasFocus;let calls=0;Document.prototype.hasFocus=function(){return ++calls<3&&original.call(this)}',
        }
        if case in scripts:
            _invoke(target.supervisor,target.leaf_sid,target.leaf_guard,'function(){'+scripts[case]+';return true}')
        # Observe the runtime's original diagnostic plane, never replace it.
        diag = _fill_diagnostic.get()
        assert isinstance(diag, dict)
        try:
            return original_fill(target, value, expires_at=expires_at)
        finally:
            diagnostics.append(dict(diag))
    monkeypatch.setattr(vault_ingress, 'fill_verification_code', fill)
    refused = case in ('clone','focus','history','title_source','canary_competing','guard_diagnostic','focus_diagnostic')
    partial = case in ('focus','guard_diagnostic','focus_diagnostic')
    pending, sent = [], []
    async def submit(chat_id, content, metadata):
        assert chat_id == '-600'
        token = urlsplit(content.split('form: ',1)[1].split(' for ',1)[0]).fragment
        status, descriptor = await asyncio.to_thread(post,settings,root,'/session',{'token':token,'initData':''})
        assert status == 200 and descriptor['target']['confirmation_required'] is True
        assert descriptor['target']['validation'] == spec()['validation']
        status, body = await asyncio.to_thread(post,settings,root,'/submit',{'token':token,'initData':'','values':['123456'],'confirmed':True},timeout=120)
        assert (status,body) == ((409,{'error':'fill_unconfirmed'}) if refused else (200,{'filled':True}))
    async def send(chat_id, content, metadata=None):
        sent.append(True)
        pending.append(asyncio.create_task(submit(chat_id,content,metadata)))
        return SimpleNamespace(success=True)
    async def drain():
        await asyncio.gather(*pending)
    with running_gateway_loop() as loop, registered(monkeypatch,home,settings=settings) as (_,gateway), _profile_runtime_scope(home,{}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM:SimpleNamespace(send=send)}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM,user_id='7',chat_id='-600',chat_type='group'),text='synthetic')
        invoke_hook('pre_gateway_dispatch',event=event,gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram',user_id='7',chat_id='-600',chat_type='group',session_id=nested.sup.task_id,session_key='key',cron_session='')
        try:
            raw = registry.dispatch('secure_env_vault',{'origin':origin,'label':'Synthetic','mode':'code','parent':nested.parent,'target_spec':spec()},task_id=nested.sup.task_id,session_id=nested.sup.task_id)
            asyncio.run_coroutine_threadsafe(drain(),loop).result(timeout=180)
        finally:
            sc.clear_session_vars(tokens)
    result = json.loads(raw)
    assert result['status'] == ('unknown' if refused else 'filled'), result
    assert sent == [True] and len(diagnostics) == 1
    assert '123456' not in raw
    assert leaf.evaluate("originalCells.map(e=>e.value).join('')") == ('1' if partial else '' if refused else '123456')
    if not refused:
        assert leaf.evaluate("originalCells.every((e,i)=>e===document.querySelector('[name=code'+i+']')&&!e.hasAttribute('value'))")
    if case in ('guard_diagnostic','focus_diagnostic','focus'):
        assert diagnostics[0]['writes_attempted'] == diagnostics[0]['writes_confirmed'] == 1
        assert diagnostics[0]['reason'] == {'guard_diagnostic':'guard_refused','focus_diagnostic':'document_focus_lost','focus':'unexpected_focus'}[case]
    assert not (home/'vault').exists() and not (home/'.env').exists()
