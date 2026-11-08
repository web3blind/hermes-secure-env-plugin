"""Across-mode native presentation tolerance and protected consent/purpose."""
import json
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from exact_card_helpers import page, registered_fill, SECRET
from secure_env_ingress import code_targets as ct


@pytest.mark.parametrize('explicit',[False,True])
def test_code_presentation_changes_are_not_authority(nested,explicit):
    origin,leaf=setup_chain(nested)
    spec=None
    if explicit:
        from test_exact_code_browser import spec as make_spec
        leaf.evaluate("document.querySelector('input').id='challenge'")
        spec=make_spec(6)
    target=ct.discover(origin,'Synthetic verification',nested.sup.task_id,parent=nested.parent,target_spec=spec)[0]
    try:
        leaf.evaluate("const e=document.querySelector('input');e.className='new';e.style.transform='translateX(50px)';e.form.action='https://other.test';e.name='new-name';history.replaceState({},'','/route')")
        assert ct.fill(target,'A1B2C3',time.monotonic()+10)
        assert leaf.evaluate("document.querySelector('input').value==='A1B2C3'&&!window.submitted")
    finally:
        ct.release(target)


@pytest.mark.parametrize('phase',['focus','input'])
def test_explicit_card_has_no_presentation_history_locks(nested,tmp_path,monkeypatch,phase):
    origin,leaf,s=page(nested)
    leaf.evaluate("phase=>{const p=document.querySelector('#pan');p.addEventListener(phase,()=>{p.form.className='dynamic';p.style.transform='translateX(50px)';p.setAttribute('value',p.value);p.form.action='https://other.test'},{once:true})}",phase)
    result,seen,resolved=registered_fill(nested,tmp_path,monkeypatch,origin,s)
    assert result['status']=='filled',result
    assert len(seen)==len(resolved)==1
    assert leaf.evaluate('window.writes===4&&!window.submitted&&!window.clicked')


def test_explicit_partial_card_and_complex_hint(nested,tmp_path,monkeypatch):
    origin,leaf,s=page(nested)
    s['fields']=[s['fields'][0]]
    s['fields'][0]['selector']='form input[id="pan"]'
    result,seen,resolved=registered_fill(nested,tmp_path,monkeypatch,origin,s)
    assert result['status']=='filled' and result['filled_fields']==1,result
    assert len(seen)==len(resolved)==1
    assert leaf.evaluate('window.writes===1&&!window.submitted&&!window.clicked')


@pytest.mark.parametrize('topology',['top','same'])
@pytest.mark.parametrize('choice',['once','deny'])
@pytest.mark.parametrize('incomplete',[False,True])
def test_native_automatic_payment_available_fields(nested,tmp_path,monkeypatch,choice,incomplete,topology):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from agent.vault_backends.local import LocalLoginBackend
    origin,leaf,s=page(nested,topology=topology)
    leaf.evaluate("incomplete=>{const roles={pan:'cc-number',holder:'cc-name',exp:'cc-exp',cvc:'cc-csc'};for(const [id,role] of Object.entries(roles)){const e=document.getElementById(id);if(incomplete&&id!=='pan')e.remove();else e.autocomplete=role}const p=document.querySelector('#pan');p.addEventListener('focus',()=>{p.className='anything';p.style.transform='translateX(30px)';p.form.action='https://other.test'},{once:true})}",incomplete)
    runtime,settings,home,_=make_runtime(tmp_path,mini=False)
    runtime.close()
    handle=VaultStore(home/'vault').add_item('payment','Synthetic card',SECRET,origin=origin).id
    resolved=[]
    original=LocalLoginBackend.resolve_secret
    def resolve(self,h):
        resolved.append(h)
        return original(self,h)
    monkeypatch.setattr(LocalLoginBackend,'resolve_secret',resolve)
    with registered(monkeypatch,home,settings=settings),_profile_runtime_scope(home,{}),payment_consent(choice,session=nested.sup.task_id) as seen:
        raw=registry.dispatch('secure_payment_fill',{'handle':handle,'parent':nested.parent,'origin':origin},task_id=nested.sup.task_id,session_id=nested.sup.task_id)
    result=json.loads(raw)
    assert result['status']==('filled' if choice=='once' else 'payment_declined'),result
    assert len(seen)==1
    assert len(resolved)==(1 if choice=='once' else 0)
    assert leaf.evaluate('window.writes')==((1 if incomplete else 4) if choice=='once' else 0)
    assert SECRET['card_number'] not in raw
    assert leaf.evaluate('!window.submitted&&!window.clicked')


def test_native_password_type_cvc_with_payment_autocomplete(nested,tmp_path,monkeypatch):
    origin,leaf,s=page(nested)
    leaf.evaluate("document.querySelector('#cvc').type='password';document.querySelector('#cvc').autocomplete='cc-csc'")
    result,seen,resolved=registered_fill(nested,tmp_path,monkeypatch,origin,s)
    assert result['status']=='filled',result
    assert len(seen)==len(resolved)==1
    assert leaf.evaluate('window.writes===4&&!window.submitted&&!window.clicked')

def test_opaque_url_ancestor_does_not_veto_https_code_destination(nested):
    from secure_env_ingress import code_targets as codes
    origin,leaf=setup_chain(nested)
    destination=leaf.url
    nested.page.set_content('<iframe src="about:blank"></iframe>')
    middle=nested.page.frames[-1]
    middle.set_content('<iframe src="'+destination+'"></iframe>')
    leaf=middle.child_frames[-1]
    leaf.wait_for_selector('input')
    targets=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)
    try:
        assert len(targets)==1
        assert codes.fill(targets[0],'123456',time.monotonic()+60)
        assert leaf.evaluate('!!document.querySelector("input").value')
    finally:
        for target in targets:
            codes.release(target)

@pytest.mark.parametrize('remaining',[0,3])
def test_native_payment_skips_unavailable_slots_without_a_complete_card_census(nested,tmp_path,monkeypatch,remaining):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    origin,leaf,_=page(nested,topology='top')
    leaf.evaluate('''()=>{const roles={pan:'cc-number',holder:'cc-name',exp:'cc-exp',cvc:'cc-csc'};for(const [id,role] of Object.entries(roles))document.getElementById(id).autocomplete=role}''')
    runtime,settings,home,_=make_runtime(tmp_path,mini=False)
    runtime.close()
    handle=VaultStore(home/'vault').add_item('payment','Synthetic card',SECRET,origin=origin).id
    with registered(monkeypatch,home,settings=settings),_profile_runtime_scope(home,{}):
        captured=nested.capture()
        def unavailable():
            script='document.querySelector("#cvc").removeAttribute("data-hermes-vault-slot")' if remaining else 'document.querySelectorAll("input").forEach(e=>e.removeAttribute("data-hermes-vault-slot"))'
            captured.call('Runtime.evaluate',{'expression':script},session_id=captured.page_session_id)
        with payment_consent('once',session=nested.sup.task_id,before_decision=unavailable):
            raw=registry.dispatch('secure_payment_fill',{'handle':handle,'parent':nested.parent,'origin':origin},task_id=nested.sup.task_id,session_id=nested.sup.task_id)
    result=json.loads(raw)
    assert result['status']==('filled' if remaining else 'unknown'),result
    if remaining:
        assert result['filled_fields']==remaining
    assert leaf.evaluate('window.writes')==remaining
    assert leaf.evaluate('!window.submitted&&!window.clicked')

@pytest.mark.parametrize('matches',[True,False])
def test_requested_resume_compares_current_native_stamped_clone(nested,tmp_path,monkeypatch,matches):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    origin,leaf,_=page(nested,topology='top')
    leaf.evaluate('''()=>{const roles={pan:'cc-number',holder:'cc-name',exp:'cc-exp',cvc:'cc-csc'};for(const [id,role] of Object.entries(roles))document.getElementById(id).autocomplete=role}''')
    runtime,settings,home,_=make_runtime(tmp_path,mini=False)
    runtime.close()
    handle=VaultStore(home/'vault').add_item('payment','Synthetic card',SECRET,origin=origin).id
    with registered(monkeypatch,home,settings=settings),_profile_runtime_scope(home,{}):
        arguments={'handle':handle,'parent':nested.parent,'origin':origin}
        with payment_consent('once',session=nested.sup.task_id):
            first=json.loads(registry.dispatch('secure_payment_fill',arguments,task_id=nested.sup.task_id,session_id=nested.sup.task_id))
        assert first['status']=='filled',first
        captured=nested.capture()
        def clone():
            script='const e=document.querySelector("#pan"),c=e.cloneNode(true);e.replaceWith(c);'
            if not matches:
                script+='c.value="1111111111111111";'
            captured.call('Runtime.evaluate',{'expression':script},session_id=captured.page_session_id)
        with payment_consent('once',session=nested.sup.task_id,before_decision=clone):
            second=json.loads(registry.dispatch('secure_payment_fill',dict(arguments,resume_existing=True),task_id=nested.sup.task_id,session_id=nested.sup.task_id))
    assert second['status']==('filled' if matches else 'target_refused'),second
    if matches:
        assert second['resumed_fields']==4
    assert leaf.evaluate('window.writes===4&&!window.submitted&&!window.clicked')

