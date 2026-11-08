"""Protected native-classified fill of byte-exact public Computop assets.

Local synthetic origins and temporary Vault only; no submission or payment.
"""
import json
import pytest
from test_nested_code import nested as nested
from computop_fixture import MANIFEST, ROOT, markup, ready
from exact_card_helpers import SECRET


@pytest.mark.parametrize('provider',['https://parent.test','https://pay.test'])
@pytest.mark.parametrize('choice',['once','deny'])
def test_registered_provider_native_parity(nested,tmp_path,monkeypatch,provider,choice,caplog):
    from agent.vault_store import VaultStore,PAYMENT_FIELDS
    from agent.vault_login_classifier import build_inspection_js,LoginControl,classify_checkout_control,select_checkout_fills
    from agent.vault_backends.local import LocalLoginBackend
    from test_runtime_e2e import make_runtime
    from generic_helpers import registered
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    from secure_env_ingress import payment_fill

    def assets(route):
        row=next((a for a in MANIFEST if route.request.url.endswith('/'+a['name'])),None)
        if row:
            mime='text/css' if row['name'].endswith('.css') else 'image/svg+xml' if row['name'].endswith('.svg') else 'font/woff2'
            route.fulfill(body=(ROOT/row['name']).read_bytes(),content_type=mime)
        else:
            route.fallback()
    nested.context.route('**/*',assets)
    nested.pages['https://parent.test/root']='<iframe width=576 height=334 src="'+provider+'/fields"></iframe>'
    nested.pages[provider+'/fields']=markup(provider)
    nested.page.goto('https://parent.test/root')
    nested.page.frame_locator('iframe').locator('#_KKnr').wait_for()
    leaf=next(f for f in nested.page.frames if f.url==provider+'/fields')
    ready(leaf)
    assert leaf.evaluate("[creditCardHolder,_KKnr,expiry_date,cccvc].every(e=>e.value==='')")
    rows=json.loads(leaf.evaluate(build_inspection_js('synthetic-native-comparison')))
    classified=[c for row in rows if (c:=classify_checkout_control(LoginControl.from_dict(row))) is not None]
    native=select_checkout_fills(classified,SECRET,PAYMENT_FIELDS)
    # Native does not contain the removed provider/name-specific cc-name fallback.
    assert {f['token'] for f in native}>={'cc-number','cc-exp','cc-csc'}
    runtime,settings,home,_=make_runtime(tmp_path,mini=False)
    runtime.close()
    handle=VaultStore(home/'vault').add_item('payment','Synthetic card',SECRET,origin=provider).id
    resolutions=[]
    resolve=LocalLoginBackend.resolve_secret
    def resolve_secret(self,h):
        resolutions.append(h)
        return resolve(self,h)
    monkeypatch.setattr(LocalLoginBackend,'resolve_secret',resolve_secret)
    writes=[]
    invoke=payment_fill._invoke
    def protected(sup,sid,obj,function,args=()):
        if 'this.write(' in function:
            writes.append(args[0])
        return invoke(sup,sid,obj,function,args)
    monkeypatch.setattr(payment_fill,'_invoke',protected)
    try:
        with registered(monkeypatch,home,settings=settings),_profile_runtime_scope(home,{}),payment_consent(choice,session=nested.sup.task_id) as approvals:
            raw=registry.dispatch('secure_payment_fill',{'handle':handle,'parent':nested.parent,'origin':provider},task_id=nested.sup.task_id,session_id=nested.sup.task_id)
        result=json.loads(raw)
        assert len(approvals)==1
        assert result['status']==('filled' if choice=='once' else 'payment_declined'),result
        assert len(resolutions)==(1 if choice=='once' else 0)
        assert len(writes)==(len(native) if choice=='once' else 0)
        assert leaf.evaluate("!check_agb.checked&&submissions===0")
        expected_holder=choice=='once' and any(f['token']=='cc-name' for f in native)
        assert leaf.evaluate("!!creditCardHolder.value")==expected_holder
        if choice=='once':
            assert result['filled_fields']==len(native)
            assert leaf.evaluate("_KKnr.value==='4242 4242 4242 4242'&&expiry_date.value==='12/31'&&cccvc.value==='123'&&document.SSLForm.KKName.value==='VISA'")
        else:
            assert leaf.evaluate("[creditCardHolder,_KKnr,expiry_date,cccvc].every(e=>e.value==='')")
        assert SECRET['card_number'] not in raw+json.dumps(approvals)+caplog.text
    finally:
        nested.context.unroute('**/*',assets)
