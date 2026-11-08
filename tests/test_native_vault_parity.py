"""Native-differential destination policy; synthetic values, real CDP/dispatch."""
import json
import pytest
from test_retained_login_browser import browser as browser, env as env, backend, registered
from test_retained_login_frameworks import mount
from secure_env_ingress import login_fill as lf


# All mutation strings below are fixed synthetic test stimuli, not untrusted JS.
@pytest.mark.parametrize('framework',['vue','vuetify'])
@pytest.mark.parametrize('change',[
 "p.className+=' arbitrary';p.style.transform='translateX(20px)'",
 "p.form.action='/other';p.form.action='/signin'",
 "u.value='changed';u.dispatchEvent(new Event('input',{bubbles:true}));u.value='account@example.test'",
 "p.type='text';p.type='password'",
 "p.form.insertAdjacentHTML('beforeend','<input type=password>')",
 "p.setAttribute('value','public-reflection')",
 "history.replaceState({},'', '/same-origin-route')",
])
def test_native_allows_presentation_and_history(env,monkeypatch,framework,change):
    mount(env,framework)
    env.page.evaluate("s=>{const p=document.querySelector('#p'),u=document.querySelector('#u');p.addEventListener('focus',()=>{eval(s)},{once:true})}",change)
    handle,resolved=backend(env,monkeypatch)
    result=registered(env,monkeypatch,handle)
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate('document.querySelector("#p").value.length>0&&!window.submitted')


@pytest.mark.parametrize('mutation',[
 "document.querySelector('#p').removeAttribute('data-hermes-vault-slot')",
 "document.querySelector('#p').type='text'",
 "document.querySelector('#p').remove()",
])
def test_native_selected_slot_negative_before_resolver(env,monkeypatch,mutation):
    handle,resolved=backend(env,monkeypatch)
    target=lf.discover(env.browser.sup.task_id,env.parent,env.origin,lambda:None)
    try:
        env.page.evaluate(mutation)
        result=lf.fill_login(target,handle,lambda:None)
        assert result['status']=='target_refused'
        assert not resolved
        assert env.page.evaluate('window.writes===0')
    finally:
        target.lease.close()


@pytest.mark.parametrize('html',[
 '<input id=p type=password autocomplete=new-password>',
 '<input id=p type=password disabled>',
 '<input id=p type=password readonly>',
 '<input id=p type=password style="display:none">',
 '<input id=p type=text>',
 '<input id=p type=text autocomplete=current-password><input type=password>',
])
def test_native_inspection_classifier_negative(env,monkeypatch,html):
    env.page.set_content(html)
    handle,resolved=backend(env,monkeypatch)
    assert registered(env,monkeypatch,handle)['status']=='target_refused'
    assert not resolved


def test_wrong_handle_origin_never_resolves(env,monkeypatch):
    handle,resolved=backend(env,monkeypatch,origin='https://wrong.test')
    assert registered(env,monkeypatch,handle)['status']=='target_refused'
    assert not resolved
    assert env.page.evaluate('window.writes===0')


def test_highest_native_score_and_dom_tie_order(env,monkeypatch):
    env.page.set_content('<input id=first type=password><input id=best type=password autocomplete=current-password><input id=last type=password autocomplete=current-password>')
    handle,_=backend(env,monkeypatch)
    assert registered(env,monkeypatch,handle)['status']=='filled'
    assert env.page.evaluate('!!document.querySelector("#best").value&&!document.querySelector("#first").value&&!document.querySelector("#last").value')


@pytest.mark.parametrize('mutation',[
 "document.querySelector('#p').style.opacity='0'",
 "document.querySelector('#p').setAttribute('name','new-name')",
 "document.querySelector('#p').removeAttribute('data-hermes-vault-slot')",
 "document.querySelector('#p').type='text'",
])
def test_native_helper_differential(env,monkeypatch,mutation):
    from agent.vault_login_classifier import build_inspection_js, build_fill_js
    env.page.evaluate(build_inspection_js('comparison'))
    env.page.evaluate(mutation)
    native=json.loads(env.page.evaluate(build_fill_js([{'index':1,'token':'current-password','value':'SYNTHETIC'}],env.origin,'comparison')))
    expected=native['filled']>0
    env.page.reload()
    handle,_=backend(env,monkeypatch)
    target=lf.discover(env.browser.sup.task_id,env.parent,env.origin,lambda:None)
    try:
        env.page.evaluate(mutation)
        result=lf.fill_login(target,handle,lambda:None)
        assert (result['status']=='filled')==expected
    finally:
        target.lease.close()


@pytest.mark.parametrize('mode',['login','totp'])
@pytest.mark.parametrize('hint',[False,True])
def test_native_parent_destination_ignores_unrelated_frame_census(env,monkeypatch,mode,hint):
    attrs='type=password autocomplete=current-password' if mode=='login' else 'autocomplete=one-time-code name=otp'
    env.page.set_content('<input id=p '+attrs+'>'+('<iframe></iframe>'*25))
    handle,resolved=backend(env,monkeypatch,mode=mode)
    options={'frame':'top'} if mode=='login' and hint else {'field_selector':'#p'} if hint else {}
    result=registered(env,monkeypatch,handle,mode=mode,**options)
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate('!!document.querySelector("#p").value')


def test_saved_provider_otp_does_not_inherit_human_code_format_policy(env,monkeypatch):
    from agent.vault_backends.local import LocalLoginBackend
    env.page.set_content('<input id=p autocomplete=one-time-code>')
    handle,resolved=backend(env,monkeypatch,mode='totp')
    # Synthetic provider result exercises native value mapping, not a real key.
    def provider(self,h):
        resolved.append(h)
        return 'SyntheticProviderOTP20'
    monkeypatch.setattr(LocalLoginBackend,'resolve_otp',provider)
    result=registered(env,monkeypatch,handle,mode='totp')
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate('document.querySelector("#p").value.length')==len('SyntheticProviderOTP20')


def test_saved_otp_keeps_native_unsplit_selection_without_maxlength(env,monkeypatch):
    from agent.vault_backends.local import LocalLoginBackend
    markup='<form><div>'+''.join('<input autocomplete=one-time-code name=code-'+str(i)+' inputmode=numeric pattern="[0-9]">' for i in range(6))+'</div></form>'
    env.page.set_content(markup)
    handle,resolved=backend(env,monkeypatch,mode='totp')
    def provider(self,h):
        resolved.append(h)
        return '123456'
    monkeypatch.setattr(LocalLoginBackend,'resolve_otp',provider)
    result=registered(env,monkeypatch,handle,mode='totp')
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert env.page.evaluate("[...document.querySelectorAll('input')].map(e=>e.value.length)")==[6,0,0,0,0,0]

@pytest.mark.parametrize('mode',['login','totp'])
def test_native_url_origin_is_authority_in_sandboxed_https_document(env,monkeypatch,mode):
    from agent.vault_login_classifier import build_inspection_js, build_fill_js
    attrs='type=password autocomplete=current-password' if mode=='login' else 'autocomplete=one-time-code'
    url='https://sandbox.test/native'
    env.browser.pages[url]='<input id=p '+attrs+'>'
    env.page.set_content('<iframe sandbox="allow-scripts" src="'+url+'"></iframe>')
    leaf=env.page.frames[-1]
    leaf.wait_for_selector('#p')
    assert leaf.evaluate('self.origin')=='null'
    env.origin='https://sandbox.test'
    assert leaf.evaluate('location.origin')==env.origin
    leaf.evaluate(build_inspection_js('native-sandbox'))
    token='current-password' if mode=='login' else 'one-time-code'
    native=json.loads(leaf.evaluate(build_fill_js([{'index':0,'token':token,'value':'SYNTHETIC'}],env.origin,'native-sandbox')))
    assert native['filled']==1
    leaf.evaluate('document.querySelector("#p").value=""')
    handle,resolved=backend(env,monkeypatch,mode=mode)
    result=registered(env,monkeypatch,handle,mode=mode)
    assert result['status']=='filled',result
    assert len(resolved)==1
    assert leaf.evaluate('!!document.querySelector("#p").value')

@pytest.mark.parametrize('remaining',[0,5])
def test_saved_otp_skips_individually_unavailable_native_slots(env,monkeypatch,remaining):
    from agent.vault_backends.local import LocalLoginBackend
    from agent.vault_login_classifier import build_inspection_js,build_fill_js,build_otp_fills,LoginControl,classify_otp_controls
    from secure_env_ingress import nested_code as nc
    markup='<form>'+('<input autocomplete=one-time-code maxlength=1>'*6)+'</form>'
    env.page.set_content(markup)
    rows=json.loads(env.page.evaluate(build_inspection_js('native-partial')))
    controls=classify_otp_controls([LoginControl.from_dict(r) for r in rows])
    mutation='n=>[...document.querySelectorAll("input")].forEach((e,i)=>{if(n===0||i===2)e.removeAttribute("data-hermes-vault-slot")})'
    env.page.evaluate(mutation,remaining)
    native=json.loads(env.page.evaluate(build_fill_js(build_otp_fills(controls,'123456'),env.origin,'native-partial')))
    assert native['filled']==remaining
    env.page.set_content(markup)
    handle,resolved=backend(env,monkeypatch,mode='totp')
    def provider(self,h):
        resolved.append(h)
        return '123456'
    monkeypatch.setattr(LocalLoginBackend,'resolve_otp',provider)
    target=nc.discover(env.origin,'Synthetic',env.browser.sup.task_id,parent=env.parent,saved_otp=True)[0]
    try:
        env.page.evaluate(mutation,remaining)
        result=lf.fill_totp(target,handle,lambda:None)
        assert result['status']==('filled' if remaining else 'unknown'),result
        assert len(resolved)==1
        assert env.page.evaluate('[...document.querySelectorAll("input")].filter(e=>e.value).length')==native['filled']
    finally:
        nc.release(target)

