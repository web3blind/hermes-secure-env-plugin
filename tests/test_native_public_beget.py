"""Actual public Beget, disposable target and Vault, protected synthetic fill.

No production account, no submission/click, no untrusted destination mocks.
"""
import hashlib
import importlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from test_retained_login_browser import backend


def test_public_beget_runtime_directory(tmp_path,monkeypatch):
    from test_runtime_e2e import make_runtime
    runtime,settings,home,_=make_runtime(tmp_path,mini=False)
    runtime.close()
    monkeypatch.setenv('HERMES_HOME',str(home))
    env=SimpleNamespace(home=home,settings=settings,browser=SimpleNamespace())
    import yaml
    from hermes_cli.plugins import PluginManager
    from gateway.run import _profile_runtime_scope
    from gateway import session_context as sc
    from tools.registry import registry
    source=Path(__file__).resolve().parents[1]/'secure_env_ingress'
    slot=env.home/'plugins/secure-env-ingress'
    shutil.copytree(source,slot,ignore=shutil.ignore_patterns('__pycache__'))
    (env.home/'config.yaml').write_text(yaml.safe_dump({'plugins':{'enabled':['secure-env-ingress'],'entries':{'secure-env-ingress':{'settings':env.settings}}}}))
    # Separate public host transport, owning only a new disposable context.
    from playwright.sync_api import sync_playwright
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    import urllib.request
    with urllib.request.urlopen('http://127.0.0.1:18800/json/version') as response:
        endpoint=json.load(response)['webSocketDebuggerUrl']
    public_sup=CDPSupervisor('native-parity-public-beget',endpoint)
    public_sup.start()
    with SUPERVISOR_REGISTRY._lock:
        SUPERVISOR_REGISTRY._by_task[public_sup.task_id]=public_sup
    env.browser.sup=public_sup
    pw=sync_playwright().start()
    public_browser=pw.chromium.connect_over_cdp(endpoint)
    context=public_browser.new_context(proxy={'server':'socks5://127.0.0.1:18081'})
    page=context.new_page()
    manager=None
    try:
        page.goto('https://cp.beget.com/login',wait_until='domcontentloaded',timeout=60000)
        try:
            page.locator('#password').wait_for(timeout=20000)
        except Exception:
            print('PUBLIC_NETWORK_DIAGNOSTIC '+json.dumps({'url':page.url,'title':page.title(),'text':page.locator('body').inner_text()[:3000],'html':page.content()[:3000]}))
            raise
        page.locator('#login').fill('syntheticaccount')
        page.evaluate("window.syntheticSubmitted=false;document.addEventListener('submit',e=>{window.syntheticSubmitted=true;e.preventDefault()},true)")
        session=context.new_cdp_session(page)
        parent=session.send('Target.getTargetInfo')['targetInfo']['targetId']
        session.detach()
        with _profile_runtime_scope(env.home,{}):
            manager=PluginManager(scope_key=str(env.home))
            manager.discover_and_load()
            row=next(r for r in manager.list_plugins() if r['name']=='secure-env-ingress')
            assert row['enabled'] and not row['error'],row
            namespace=manager._directory_module_name(manager._plugins['secure-env-ingress'].manifest)
            module=importlib.import_module(namespace+'.login_fill')
            assert Path(module.__file__).resolve()==slot/'login_fill.py'
            assert hashlib.sha256((slot/'native_fill.py').read_bytes()).digest()==hashlib.sha256((source/'native_fill.py').read_bytes()).digest()
            handle,resolved=backend(SimpleNamespace(home=env.home,origin='https://cp.beget.com'),monkeypatch)
            tokens=sc.set_session_vars(platform='telegram',user_id='7',chat_id='7',chat_type='dm',session_id=env.browser.sup.task_id,session_key='synthetic-public-beget',cron_session='')
            try:
                raw=registry.dispatch('secure_login_fill',{'handle':handle,'parent':parent,'origin':'https://cp.beget.com','field_selector':'#password','frame':'top'},task_id=env.browser.sup.task_id,session_id=env.browser.sup.task_id)
            finally:
                sc.clear_session_vars(tokens)
            result=json.loads(raw)
            assert result['status']=='filled',result
            assert len(resolved)==1
            assert 'Synthetic-Long-Password!' not in raw
            state=page.evaluate('({passwordPresent:!!document.querySelector("#password").value,loginUnchanged:document.querySelector("#login").value==="syntheticaccount",urlUnchanged:location.href==="https://cp.beget.com/login",submitted:window.syntheticSubmitted})')
            assert state=={'passwordPresent':True,'loginUnchanged':True,'urlUnchanged':True,'submitted':False}
            receipt={'namespace':namespace,'version':row['version'],'parent':parent,'result':result,'resolver_calls':len(resolved),'state':state,'login_sha256':hashlib.sha256((slot/'login_fill.py').read_bytes()).hexdigest(),'boundary_sha256':hashlib.sha256((slot/'native_fill.py').read_bytes()).hexdigest()}
            (Path(__file__).resolve().parents[2]/('public-beget-'+Path(__file__).resolve().parents[1].name+'.json')).write_text(json.dumps(receipt,indent=2))
            print('PUBLIC_BEGET_RECEIPT '+json.dumps(receipt))
    finally:
        if manager:
            manager.unload()
        context.close()
        public_sup.stop()
        with SUPERVISOR_REGISTRY._lock:
            SUPERVISOR_REGISTRY._by_task.pop(public_sup.task_id,None)
        pw.stop()
