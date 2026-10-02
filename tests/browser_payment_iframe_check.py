"""0.7.3 registered protected dynamic iframe fill, isolated real Chromium + native queue.

Synthetic routed HTTPS documents only; Stripe-documented test card. No live
Vault, authenticated profile clone, external site, submit, charge or installation.
Supports checkout source or extracted-wheel package via PYTHONPATH.
"""
import json
import os
from pathlib import Path
import tempfile
import urllib.request

import pytest
from playwright.sync_api import sync_playwright
from generic_helpers import registered
from test_runtime_e2e import make_runtime
from payment_consent_helpers import payment_consent
from payment_fixture_helpers import HOST


SEPARATE = ['cc-number', 'cc-name', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'postal-code']
COMBINED = ['cc-number', 'cc-name', 'cc-exp', 'cc-csc', 'postal-code']
SECRET = dict(card_number='4242424242424242', cardholder_name='Synthetic Holder',
              exp_month='12', exp_year='2031', cvc='123', billing_postal_code='12345')


def form(tokens, year_select=False):
    fields = []
    for i, token in enumerate(tokens):
        element = (f'<select id="f{i}" autocomplete="{token}"><option value="">Choose</option><option value="2031">2031</option></select>'
            if year_select and token == 'cc-exp-year' else f'<input id="f{i}" autocomplete="{token}"' + (' maxlength="5" placeholder="MM/YY"' if token == 'cc-exp' else '') + '>')
        fields.append(f'<label for="f{i}">{token}</label>' + element)
    return '<form onsubmit="window.submissions++;return false">' + ''.join(fields) + '<button>Pay</button></form>'


def main():
    from agent.vault_store import VaultStore
    from gateway.run import _profile_runtime_scope
    from tools import browser_tool as bt
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from tools.registry import registry
    from secure_env_ingress.code_targets import _call, _evaluate

    endpoint = os.environ.get('SENV_TEST_CDP', 'http://127.0.0.1:18800')
    with urllib.request.urlopen(endpoint + '/json/version', timeout=3) as response:
        ws = json.load(response)['webSocketDebuggerUrl']
    with tempfile.TemporaryDirectory(prefix='senv-frame-', dir=os.environ['TMPDIR']) as directory, pytest.MonkeyPatch.context() as monkeypatch:
        runtime, settings, home, _ = make_runtime(Path(directory), mini=False)
        runtime.close()
        monkeypatch.setenv('HERMES_HOME', str(home))
        task = 'senv-frame-isolated-' + Path(directory).name
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(endpoint, timeout=15000)
            context = browser.new_context(ignore_https_errors=True)
            supervisor = None
            try:
                page = context.new_page()
                foreign = context.new_page()
                errors = []
                page.on('pageerror', lambda e: errors.append(type(e).__name__))
                state = {'origin': 'https://pay.test', 'tokens': SEPARATE, 'siblings': 1, 'forms': 1, 'select': False}
                def route(r):
                    url = r.request.url
                    if '/parent' in url:
                        body = '<div id="move"></div>' + ''.join(f'<iframe id="frame{i}" src="{state["origin"]}/fields?slot={i}"></iframe>' for i in range(state['siblings']))
                    else:
                        body = '<script>window.submissions=0</script>' + form(state['tokens'], state['select']) * state['forms']
                    r.fulfill(status=200, content_type='text/html', body=body)
                context.route('**/*', route)
                def reset(**kwargs):
                    state.update(dict(origin='https://pay.test', tokens=SEPARATE, siblings=1, forms=1, select=False))
                    state.update(kwargs)
                    page.goto('https://merchant.test/parent', timeout=15000)
                    page.frame_locator('iframe').first.locator('input').first.wait_for()
                reset()
                foreign.goto('https://other.test/parent')
                pc = context.new_cdp_session(page)
                parent = pc.send('Target.getTargetInfo')['targetInfo']['targetId']
                pc.detach()
                fc = context.new_cdp_session(foreign)
                other = fc.send('Target.getTargetInfo')['targetInfo']['targetId']
                fc.detach()
                class Selected(CDPSupervisor):
                    async def _attach_initial_page(self):
                        self._page_session_id = sid = (await self._cdp('Target.attachToTarget', {'targetId': parent, 'flatten': True}))['result']['sessionId']
                        await self._enable_page_domains(sid, timeout=10)
                supervisor = Selected(task, ws)
                supervisor.start()
                with SUPERVISOR_REGISTRY._lock:
                    SUPERVISOR_REGISTRY._by_task[task] = supervisor
                bt._active_sessions[task] = {'session_key': task, 'owner_task_id': task}
                bt._last_active_session_key[task] = task
                store = VaultStore(home / 'vault')
                handle = store.add_item('payment', 'Synthetic card', SECRET, origin='https://pay.test').id
                same = store.add_item('payment', 'Synthetic same-process', SECRET, origin='https://merchant.test').id
                login = store.add_item('login', 'Synthetic login', {'identifier': 'synthetic', 'identifier_type': 'username', 'password': 'synthetic-password'}, origin='https://pay.test').id
                results = {}
                with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
                    def invoke(choice='once', before=None, **kwargs):
                        page.bring_to_front()
                        args = dict(handle=handle, parent=parent, origin=state['origin'])
                        args.update(kwargs)
                        with payment_consent(choice, session=task, before_decision=before) as seen:
                            result = json.loads(registry.dispatch('secure_payment_fill', args, task_id=task, session_id=task))
                        if before is not None and not page.is_closed() and page.locator('iframe').count():
                            page.frame_locator('iframe').first.locator('input').first.wait_for(timeout=10000)
                        assert SECRET['card_number'] not in json.dumps(result) + json.dumps(seen)
                        assert all(f.evaluate('window.submissions') == 0 for f in page.frames[1:])
                        return result, seen
                    def empty():
                        return all(f.locator('input,select').evaluate_all('(es)=>es.every(e=>!e.value)') for f in page.frames[1:])
                    for choice in ('deny', 'unresolved', 'missing'):
                        result, seen = invoke(choice)
                        assert result['status'] == 'payment_declined' and empty()
                        assert len(seen) == (0 if choice == 'missing' else 1)
                    results['native_consent_refusals_zero_writes'] = True
                    for invalid in (dict(handle=login), dict(origin='https://merchant.test'), dict(parent=other)):
                        result, seen = invoke(**invalid)
                        assert result['status'] == 'target_refused' and not seen and empty()
                    results['wrong_kind_origin_parent_refused'] = True
                    result, seen = invoke()
                    assert result['success'] and result['filled_fields'] == 6 and len(seen) == 1
                    values = list(SECRET.values())
                    assert page.frames[1].locator('input').evaluate_all('(es,expected)=>es.every((e,i)=>e.value===expected[i])', values)
                    assert foreign.frames[1].locator('input').evaluate_all('(es)=>es.every(e=>!e.value)')
                    def frame_ids():
                        root = _call(supervisor, 'DOM.getDocument', {'depth': 0}, supervisor._page_session_id)['result']['root']['nodeId']
                        ids = _call(supervisor, 'DOM.querySelectorAll', {'nodeId': root, 'selector': 'iframe'}, supervisor._page_session_id)['result']['nodeIds']
                        return [_call(supervisor, 'DOM.describeNode', {'nodeId': n}, supervisor._page_session_id)['result']['node']['frameId'] for n in ids]
                    frame = frame_ids()[0]
                    assert _call(supervisor, 'Target.getTargetInfo', {'targetId': frame})['result']['targetInfo']['type'] == 'iframe'
                    results['oopif_exact_six_fields_other_page_untouched'] = True
                    reset(tokens=COMBINED)
                    result, _ = invoke()
                    assert result['success'] and result['filled_fields'] == 5
                    assert page.frames[1].locator('input').evaluate_all('(es,x)=>es.every((e,i)=>e.value===x[i])',
                        [SECRET['card_number'], SECRET['cardholder_name'], '12/31', SECRET['cvc'], SECRET['billing_postal_code']])
                    results['combined_mm_yy_2031_to_31'] = True
                    reset(origin='https://merchant.test', select=True)
                    result, _ = invoke(handle=same)
                    assert result['success'] and result['filled_fields'] == 6
                    assert page.frames[1].locator('input,select').evaluate_all('(es,x)=>es.every((e,i)=>e.value===x[i])', values)
                    results['same_process_separate_year_select_four_digits'] = True
                    # Dynamic hosted forms format number and update unrelated UI.
                    for dynamic_origin, dynamic_handle in [('https://pay.test', handle), ('https://merchant.test', same)]:
                        reset(origin=dynamic_origin)
                        page.frames[1].evaluate("""() => {
                          const icon=document.createElement('span'); icon.id='brand';
                          icon.style.cssText='display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint';
                          const hidden=document.createElement('input'); hidden.type='hidden'; hidden.id='cardtype';
                          document.querySelector('form').append(icon,hidden);
                          document.querySelector('input').addEventListener('input',e=>{
                            e.target.value=e.target.value.replace(/([0-9]{4})(?=[0-9])/g,'$1 ');
                            icon.style.display='block'; hidden.setAttribute('value','visa');
                          });
                        }""")
                        page.frames[1].evaluate(HOST)
                        result, _ = invoke(handle=dynamic_handle)
                        assert result['success'] and result['filled_fields'] == 6, 'dynamic hosted form must complete'
                        assert page.frames[1].locator('input:not([type=hidden])').evaluate_all(
                            '(es,x)=>es.every((e,i)=>i===0 ? e.value.replace(/ /g,"")===x[i] : e.value===x[i])', values)
                    results['dynamic_oopif_and_same_process_format_icon_hidden'] = True
                    for overlay_origin, overlay_handle in [('https://pay.test', handle), ('https://merchant.test', same)]:
                        for event in ['focus', 'input', 'change']:
                            for revert in [False, True]:
                                reset(origin=overlay_origin)
                                page.frames[1].evaluate("""([event,revert]) => {
                                  const icon=document.createElement('span');
                                  icon.style.cssText='display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint';
                                  document.querySelector('form').append(icon);
                                  document.querySelector('input').addEventListener(event,()=>{
                                    const old=icon.getAttribute('style');
                                    icon.style.cssText='display:block;position:fixed;inset:0;z-index:99999;background:white';
                                    icon.getBoundingClientRect();
                                    if(revert) icon.setAttribute('style',old);
                                  },{once:true});
                                }""", [event, revert])
                                result, _ = invoke(handle=overlay_handle)
                                assert not result['success'] and result['status'] == ('target_refused' if event == 'focus' else 'unknown'), (event, revert)
                                assert page.frames[1].evaluate("Array.from(document.querySelectorAll('input')).slice(1).every(e=>e.value==='') && window.submissions===0")
                    results['bounded_icon_overlay_callbacks_refuse_before_later_writes'] = True
                    # Separate layout attacks: only the old display toggle changes.
                    layouts = {
                        'negative_margin_overlay': '#brand {margin-left:-24px;background:black} #f4 {width:24px}',
                        'normal_wrapping_clipping': 'form {width:420px;height:24px;overflow:hidden}',
                        'flex_contribution': 'form {display:flex}',
                        'grid_contribution': 'form {display:grid;grid-template-columns:repeat(3,110px)} form input {width:90px}',
                        'latent_min_width': '#brand {min-width:400px}',
                        'latent_min_height': '#brand {min-height:400px}',
                    }
                    for layout_origin, layout_handle in [('https://pay.test', handle), ('https://merchant.test', same)]:
                        for name, css in layouts.items():
                            for event in ['focus', 'input', 'change']:
                                for revert in [False, True]:
                                    reset(origin=layout_origin)
                                    page.frames[1].evaluate("""([css,event,revert]) => {
                                      const icon=document.createElement('span');icon.id='brand';
                                      icon.style.cssText='display:none;width:24px;height:16px;pointer-events:none;overflow:hidden;contain:paint';
                                      document.querySelector('#f4').after(icon);
                                      const s=document.createElement('style');s.textContent=css;document.head.append(s);
                                      document.querySelector('input').addEventListener(event,()=>{
                                        icon.style.display='inline-block';icon.getBoundingClientRect();
                                        if(revert) {icon.style.display='none';icon.getBoundingClientRect();}
                                      },{once:true});
                                    }""", [css, event, revert])
                                    result, _ = invoke(handle=layout_handle)
                                    assert result['status'] == ('target_refused' if event == 'focus' else 'unknown'), (name,event,revert)
                                    assert page.frames[1].locator('input').evaluate_all('(es,focus)=>es.slice(focus ? 0 : 1).every(e=>!e.value)', event == 'focus')
                                    assert page.frames[1].evaluate('window.submissions===0')
                    results['normal_flow_layout_persistent_and_reverted_both_process_paths'] = True
                    reset(siblings=2)
                    result, seen = invoke()
                    assert result['status'] == 'selection_required' and len(result['candidates']) == 2 and not seen
                    token = result['candidates'][1]['selection']
                    selected_frame = result['candidates'][1]['frame']
                    # The capability cannot cross handle/origin/parent scope.
                    refused, seen = invoke(selection=token, handle=same)
                    assert refused['status'] == 'target_refused' and not seen and empty()
                    result, _ = invoke(selection=token)
                    assert result['success']
                    index = frame_ids().index(selected_frame)
                    assert page.frames[index + 1].locator('input').evaluate_all('(es)=>es.every(e=>!!e.value)')
                    assert page.frames[2 - index].locator('input').evaluate_all('(es)=>es.every(e=>!e.value)')
                    replay, seen = invoke(selection=token)
                    assert replay['status'] == 'target_refused' and not seen
                    results['sibling_choice_exact_consumed_scope'] = True
                    reset(forms=2)
                    result, seen = invoke()
                    assert result['status'] == 'selection_required' and len(result['candidates']) == 2 and not seen
                    result, _ = invoke(selection=result['candidates'][1]['selection'])
                    assert result['success']
                    assert page.frames[1].locator('form').first.locator('input').evaluate_all('(es)=>es.every(e=>!e.value)')
                    results['multiple_forms_exact_choice'] = True
                    # Main-thread preparation installs event traps; approval mutation
                    # uses the existing supervisor WS in the notifier worker boundary.
                    mutations = {
                        'iframe_reparent': "document.querySelector('#move').append(document.querySelector('iframe'))",
                        'iframe_replace': "document.querySelector('iframe').outerHTML=document.querySelector('iframe').outerHTML",
                        'iframe_attribute': "document.querySelector('iframe').setAttribute('name','changed')",
                        'iframe_detach': "document.querySelector('iframe').remove()",
                        'parent_navigation': "location.hash='changed'",
                    }
                    for name, expression in mutations.items():
                        reset()
                        result, _ = invoke(before=lambda expr=expression: _evaluate(supervisor, supervisor._page_session_id, expr))
                        assert result['status'] == 'target_refused'
                        if name not in ('iframe_replace', 'iframe_reparent'):
                            assert empty()
                        results[name + '_during_consent_refused'] = True
                    def mutate_frame(expression):
                        sid = _call(supervisor, 'Target.attachToTarget', {'targetId': frame_ids()[0], 'flatten': True})['result']['sessionId']
                        try:
                            return _evaluate(supervisor, sid, expression)
                        finally:
                            _call(supervisor, 'Target.detachFromTarget', {'sessionId': sid})
                    child_mutations = {
                        'control_replace': 'document.querySelector("input").replaceWith(document.querySelector("input").cloneNode())',
                        'control_reparent': 'document.body.appendChild(document.querySelector("input"))',
                        'form_action': 'document.querySelector("form").action="/changed"',
                        'child_origin': 'location.href="https://other.test/card"',
                    }
                    for name, expression in child_mutations.items():
                        reset()
                        result, _ = invoke(before=lambda expr=expression: mutate_frame(expr))
                        assert result['status'] == 'target_refused' and empty()
                        results[name + '_during_consent_refused'] = True
                    for name, setup in {
                        'replacement': "document.querySelector('input').addEventListener('focus',()=>{let e=document.querySelector('input');e.replaceWith(e.cloneNode())},{once:true})",
                        'reparent': "document.querySelector('input').addEventListener('focus',()=>document.body.append(document.querySelector('input')),{once:true})",
                        'attributes': "document.querySelector('input').addEventListener('focus',()=>document.querySelectorAll('input')[1].disabled=true,{once:true})",
                        'navigation': "document.querySelector('input').addEventListener('focus',()=>location.hash='mutated',{once:true})",
                    }.items():
                        reset()
                        page.frames[1].evaluate(setup)
                        result, _ = invoke()
                        assert result['status'] == 'target_refused' and empty()
                        results['focus_' + name + '_zero_writes'] = True
                    reset(origin='https://merchant.test')
                    page.frames[1].evaluate("document.querySelector('input').addEventListener('focus',()=>parent.document.querySelector('iframe').setAttribute('name','changed'),{once:true})")
                    result, _ = invoke(handle=same)
                    assert result['status'] == 'target_refused' and empty()
                    results['same_process_parent_focus_mutation_zero_writes'] = True
                    reset()
                    page.frames[1].evaluate("document.querySelector('input').addEventListener('input',()=>{let e=document.querySelectorAll('input')[1];e.replaceWith(e.cloneNode())},{once:true})")
                    result, _ = invoke()
                    assert result['status'] == 'unknown'
                    assert page.frames[1].locator('input').evaluate_all('(es,x)=>es[0].value===x && es.slice(1).every(e=>!e.value)', SECRET['card_number'])
                    results['input_mutation_partial_unknown'] = True
                    # Hostile normalization never becomes a successful readback.
                    hostile = {
                        'changed_digit': "e.value=e.value.slice(0,-1)+'3'",
                        'unicode_digit': "e.value='４'+e.value.slice(1)",
                        'nbsp': "e.value=e.value.slice(0,4)+'\\u00a0'+e.value.slice(4)",
                        'hyphen': "e.value=e.value.slice(0,4)+'-'+e.value.slice(4)",
                        'letter': "e.value+='x'",
                        'leading_space': "e.value=' '+e.value",
                        'trailing_space': "e.value+=' '",
                        'tab': "e.value+='\\t'",
                    }
                    for name, mutation in hostile.items():
                        reset()
                        page.frames[1].evaluate("document.querySelector('input').addEventListener('input',({target:e})=>{" + mutation + "},{once:true})")
                        result, _ = invoke()
                        assert result['status'] == 'unknown', name
                        assert page.frames[1].locator('input').evaluate_all('(es)=>es.slice(1).every(e=>!e.value)')
                    results['hostile_number_normalization_refused'] = True
                    attacks = {
                        'replace': "let e=document.querySelectorAll('input')[1];e.replaceWith(e.cloneNode())",
                        'reparent_revert': "let e=document.querySelectorAll('input')[1],p=e.parentNode,n=e.nextSibling;document.body.append(e);p.insertBefore(e,n)",
                        'action_revert': "let e=document.querySelector('form');e.setAttribute('action','/evil');e.removeAttribute('action')",
                        'ancestor_style_revert': "let e=document.querySelector('form');e.style.display='none';e.removeAttribute('style')",
                        'disabled_revert': "let e=document.querySelectorAll('input')[1];e.disabled=true;e.disabled=false",
                        'visibility': "document.querySelectorAll('input')[1].style.visibility='hidden'",
                        'ancestor_class': "document.body.className='other'",
                        'label_text': "document.querySelector('label').textContent='Changed purpose'",
                        'label_style_revert': "let e=document.querySelector('label');e.style.visibility='hidden';e.removeAttribute('style')",
                    }
                    for event in ('focus', 'input', 'change'):
                        for name, attack in attacks.items():
                            reset()
                            page.frames[1].evaluate("document.querySelector('input').addEventListener('" + event + "',()=>{" + attack + "},{once:true})")
                            result, _ = invoke()
                            assert result['status'] == ('target_refused' if event == 'focus' else 'unknown'), event + ':' + name
                            if event == 'focus':
                                assert empty()
                    results['event_topology_state_and_reverted_attacks_refused'] = True
                    # @scope roots/limits are selector-bearing CSS authority too.
                    for event in ('focus', 'input', 'change'):
                        reset()
                        page.frames[1].evaluate("""event => {
                          const hidden=document.createElement('input');hidden.type='hidden';hidden.id='type';
                          document.querySelector('form').append(hidden);
                          const style=document.createElement('style');
                          style.textContent='@scope (form:has(#type[value="visa"])) {input {opacity:0}}';
                          document.head.append(style);
                          document.querySelector('input').addEventListener(event,()=>{
                            hidden.setAttribute('value','visa');
                            getComputedStyle(document.querySelector('input')).opacity;
                            hidden.removeAttribute('value');
                          },{once:true});
                        }""", event)
                        result, _ = invoke()
                        assert result['status'] == ('target_refused' if event == 'focus' else 'unknown'), event
                        if event == 'focus':
                            assert empty()
                        else:
                            assert page.frames[1].locator('input').evaluate_all('(es)=>es.slice(1).every(e=>!e.value)')
                    results['scope_css_reverted_focus_input_change_refused'] = True
                    for event in ('focus', 'input', 'change'):
                        reset()
                        page.frames[1].evaluate("""event => {
                          const f=document.querySelector('form');f.style.containerType='inline-size';
                          const hidden=document.createElement('input');hidden.type='hidden';f.append(hidden);
                          const s=document.createElement('style');s.textContent='@container (max-width:200px) {input {opacity:0}}';document.head.append(s);
                          document.querySelector('input').addEventListener(event,()=>{
                            hidden.setAttribute('value','visa');getComputedStyle(document.querySelector('input')).opacity;
                            hidden.removeAttribute('value');
                          },{once:true});
                        }""", event)
                        result, _ = invoke()
                        assert result['status'] == ('target_refused' if event == 'focus' else 'unknown'), event
                        if event == 'focus':
                            assert empty()
                        else:
                            assert page.frames[1].locator('input').evaluate_all('(es)=>es.slice(1).every(e=>!e.value)')
                    results['container_css_reverted_focus_input_change_refused'] = True
                    for name, attack in attacks.items():
                        reset()
                        result, _ = invoke(before=lambda expr=attack: mutate_frame('(()=>{' + expr + '})()'))
                        assert result['status'] == 'target_refused' and empty(), name
                    results['approval_reverted_and_semantic_attacks_zero_writes'] = True
                    for event in ('focus', 'input', 'change'):
                        reset()
                        # Last-field callbacks must not silently change earlier fields.
                        page.frames[1].evaluate("document.querySelectorAll('input')[5].addEventListener('" + event + "',()=>{document.querySelector('input').value='changed'},{once:true})")
                        result, _ = invoke()
                        assert result['status'] == 'unknown', event
                    reset()
                    page.frames[1].evaluate("document.querySelectorAll('input')[1].addEventListener('input',({target:e})=>{e.value+=' '},{once:true})")
                    result, _ = invoke()
                    assert result['status'] == 'unknown'
                    results['earlier_readback_and_nonnumber_exact'] = True
                    reset()
                    page.frames[1].evaluate("""() => {
                      const f=document.querySelector('form');
                      f.replaceWith(...f.childNodes);
                      const icon=document.createElement('span');icon.id='brand';document.body.append(icon);
                      document.querySelector('input').addEventListener('input',({target:e})=>{
                        e.value=e.value.replace(/([0-9]{4})(?=[0-9])/g,'$1 ');icon.style.display='block';
                      });
                    }""")
                    page.frames[1].evaluate(HOST)
                    result, _ = invoke()
                    assert result['success'] and result['filled_fields'] == 6
                    results['formless_dynamic_success'] = True
                    reset()
                    page.frames[1].evaluate("() => {const f=document.querySelector('form');f.replaceWith(...f.childNodes)}")
                    result, _ = invoke(before=lambda: mutate_frame("document.body.style.display='none';document.body.removeAttribute('style')"))
                    assert result['status'] == 'target_refused' and empty()
                    results['formless_ancestor_reverted_refused'] = True
                    for event in ('focus', 'input', 'change'):
                        reset(origin='https://merchant.test')
                        page.evaluate("""() => {
                          const frame=document.querySelector('iframe'), brand=document.createElement('span');brand.id='brand';
                          const wrapper=document.createElement('div');wrapper.style.cssText='display:flex;width:400px';
                          frame.before(wrapper);wrapper.append(brand,frame);
                          brand.style.cssText='width:0px;flex-shrink:0';
                          frame.style.cssText='flex:1;min-width:0;width:400px';
                        }""")
                        page.frames[1].evaluate("""event => {
                          const s=document.createElement('style');s.textContent='@media (max-width:200px) {input {opacity:0}}';document.head.append(s);
                          document.querySelector('input').addEventListener(event,()=>{
                            const brand=parent.document.querySelector('#brand'), old=brand.getAttribute('style');
                            brand.style.width='300px';parent.document.querySelector('iframe').getBoundingClientRect();
                            const during=getComputedStyle(document.querySelector('input')).opacity;
                            brand.setAttribute('style',old);parent.document.querySelector('iframe').getBoundingClientRect();
                            if(during!=='0' || getComputedStyle(document.querySelector('input')).opacity!=='1') throw Error('parent viewport fixture failed');
                          },{once:true});
                        }""", event)
                        result, _ = invoke(handle=same)
                        assert result['status'] == ('target_refused' if event == 'focus' else 'unknown'), event
                        if event == 'focus':
                            assert empty()
                        else:
                            assert page.frames[1].locator('input').evaluate_all('(es)=>es.slice(1).every(e=>!e.value)')
                    results['parent_viewport_reverted_mutation_refused'] = True
                    reset()
                    result, seen = invoke(choice='missing')
                    assert result['status'] == 'payment_declined' and empty()
                    reset()
                    page.frames[1].locator('input').first.evaluate('(e)=>e.maxLength=4')
                    result, _ = invoke()
                    assert result['status'] == 'target_refused' and empty()
                    results['unsupported_format_zero_writes'] = True
                    for tokens, token, expression in [
                        (COMBINED, 'cc-exp', '(e)=>e.placeholder="MM/YYYY"'),
                        (SEPARATE, 'cc-exp-year', '(e)=>e.maxLength=2'),
                        (COMBINED, 'cc-exp', '(e)=>e.type="month"'),
                    ]:
                        reset(tokens=tokens)
                        page.frames[1].locator('[autocomplete="' + token + '"]').evaluate(expression)
                        result, _ = invoke()
                        assert result['status'] == 'target_refused' and empty()
                    results['explicit_expiry_formats_fail_closed'] = True
                    reset()
                    page.locator('iframe').evaluate('(e)=>{e.setAttribute("sandbox","allow-scripts");e.src=e.src}')
                    page.frame_locator('iframe').locator('input').first.wait_for()
                    assert page.frames[1].evaluate('self.origin === "null" && location.origin === "https://pay.test"')
                    result, seen = invoke()
                    assert result['status'] in ('no_payment_frame', 'target_refused') and not seen and empty()
                    results['opaque_sandbox_actual_origin_not_url_origin'] = True
                    reset(tokens=['cc-number', 'cc-exp-month'], siblings=2)
                    result, seen = invoke()
                    assert result['status'] == 'target_refused' and not seen and empty()
                    results['split_incomplete_frames_refused'] = True
                    reset(tokens=SEPARATE, siblings=2)
                    result, _ = invoke()
                    stale_token = result['candidates'][0]['selection']
                    page.reload(wait_until='domcontentloaded', timeout=15000)
                    page.frame_locator('iframe').first.locator('input').first.wait_for()
                    result, seen = invoke(selection=stale_token)
                    assert result['status'] == 'target_refused' and not seen and empty()
                    results['selected_document_navigation_refused'] = True
                    reset(siblings=2)
                    result, _ = invoke()
                    token = result['candidates'][0]['selection']
                    page.close()
                    with payment_consent('once', session=task) as seen:
                        result = json.loads(registry.dispatch('secure_payment_fill',
                            dict(handle=handle, parent=parent, origin='https://pay.test', selection=token), task_id=task, session_id=task))
                    assert result['status'] == 'target_refused' and not seen
                    assert foreign.frames[1].locator('input').evaluate_all('(es)=>es.every(e=>!e.value)')
                    results['closed_parent_no_fallback'] = True
                assert errors == []
                print(json.dumps({'protected_iframe_browser': 'PASS', 'checks': results, 'page_errors': 0}), flush=True)
            finally:
                if supervisor is not None:
                    SUPERVISOR_REGISTRY.stop(task)
                bt._active_sessions.pop(task, None)
                bt._last_active_session_key.pop(task, None)
                context.close()
                browser.close()


if __name__ == '__main__':
    main()
