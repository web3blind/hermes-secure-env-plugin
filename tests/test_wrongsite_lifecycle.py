"""Real disposable wrong-site capabilities: final-write fence and idle cleanup."""
from dataclasses import replace
from types import SimpleNamespace
import time

import pytest

from test_nested_code import nested as chromium_fixture, setup_chain
from test_wrongsite_parent import authorize, wrongsite
from secure_env_ingress import code_targets as codes, nested_code as nc, payment_fill as pf

nested = chromium_fixture


@pytest.mark.parametrize('adapter', ['payment', 'code'])
@pytest.mark.parametrize('private', [False, True])
def test_cancelled_guards_really_close_before_release(nested, tmp_path, monkeypatch, adapter, private):
    import threading
    from secure_env_ingress.bound_cdp import BoundCDP, acquisition_scope
    if adapter == 'payment':
        payment_page(nested)
        module, origin = pf, 'https://parent.test'
    else:
        origin, _ = setup_chain(nested)
        module = nc
    other = None
    if private:
        other, _ = wrongsite(nested)
        authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    # Track real isolated-world observer/listener disposal, not Python flags.
    wrapper = r'''function(...args){
      const observers=[], added=[], removed=[];
      const MO=globalThis.MutationObserver;
      globalThis.MutationObserver=class extends MO {
        constructor(cb){super(cb);this.disposed=false;observers.push(this)}
        disconnect(){this.disposed=true;super.disconnect()}
      };
      const proto=EventTarget.prototype, add=proto.addEventListener;
      proto.addEventListener=function(...a){added.push([this,a[0],a[1]]);return add.apply(this,a)};
      let guard, closed=false;
      try {guard=(ORIGINAL)(...args)} finally {
        globalThis.MutationObserver=MO;proto.addEventListener=add;
      }
      return Object.freeze({...guard,cleanupProbe(){return closed&&observers.length>0&&observers.every(o=>o.disposed)&&
        added.length>0&&added.every(a=>removed.some(r=>r.every((x,i)=>x===a[i])))},
        close(){const remove=proto.removeEventListener;
          proto.removeEventListener=function(...a){removed.push([this,a[0],a[1]]);return remove.apply(this,a)};
          try {guard.close();closed=true} finally {proto.removeEventListener=remove}
        }});
    }'''.replace('ORIGINAL', module._GUARD)
    monkeypatch.setattr(module, '_GUARD', wrapper)
    original_request, probes = BoundCDP._request, []
    async def observe(self, method, params, sid, **kwargs):
        if method == 'Runtime.releaseObject':
            probe = await original_request(self, 'Runtime.callFunctionOn', {
                'objectId': params['objectId'], 'functionDeclaration':
                'function(){return this.cleanupProbe?this.cleanupProbe():null}',
                'returnByValue': True}, sid, cleanup=True)
            value = probe.get('result', {}).get('result', {}).get('value')
            if value is not None:
                probes.append((sid, params['objectId'], value))
        return await original_request(self, method, params, sid, **kwargs)
    monkeypatch.setattr(BoundCDP, '_request', observe)
    batch, targets = threading.Event(), []
    try:
        with acquisition_scope(batch):
            targets = (pf.discover(nested.sup.task_id, nested.parent, origin) if adapter == 'payment'
                       else codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent))
        expected = ({(t.parent_sid, t.parent_guard) for t in targets} | {(t.child_sid, t.child_guard) for t in targets}
                    if adapter == 'payment' else
                    {(t.leaf_sid, t.leaf_guard) for t in targets} | {(a[0], a[4]) for t in targets for a in t.ancestry})
        probes.clear()
        batch.set()
        for target in targets:
            with pytest.raises(ValueError, match='cancelled'):
                target.supervisor.call('Runtime.evaluate', {'expression': 'throw Error("ordinary JS must not run")'}, target.parent_sid)
            (pf.release if adapter == 'payment' else codes.release)(target)
        assert {(sid, obj) for sid, obj, _ in probes} == expected
        assert all(closed for _, _, closed in probes), probes
        assert nested.page.frames[-1].evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
        assert not nested.sup._pending_calls
        assert codes._call(nested.sup, 'Target.getTargetInfo', {}, nested.sup._page_session_id)['result']['targetInfo']['type'] == 'page'
    finally:
        for target in targets:
            (pf.release if adapter == 'payment' else codes.release)(target)
        if other:
            other.close()


def payment_page(nested):
    setup_chain(nested)
    nested.pages['https://parent.test/root'] = '<iframe src="https://parent.test/pay"></iframe>'
    form = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'
    nested.pages['https://parent.test/pay'] = form * 2
    nested.page.reload()
    nested.page.frames[-1].wait_for_selector('input')


@pytest.mark.parametrize('adapter', ['payment', 'code'])
def test_reconnect_between_final_guard_and_write(nested, tmp_path, monkeypatch, adapter):
    if adapter == 'code':
        origin, leaf = setup_chain(nested)
        module = nc
    else:
        payment_page(nested)
        origin, leaf, module = 'https://parent.test', nested.page.frames[-1], pf
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    target = (codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent) if adapter == 'code'
              else pf.discover(nested.sup.task_id, nested.parent, origin))[0]
    original = module._invoke
    old_ws, commands, reached = nested.sup._ws, [], []
    class Replacement:
        async def send(self, message):
            commands.append(message)
    def invoke(sup, sid, obj, function, *args, **kwargs):
        if 'this.write(' in function:
            reached.append(True)
            nested.sup._ws = Replacement()
        return original(sup, sid, obj, function, *args, **kwargs)
    monkeypatch.setattr(module, '_invoke', invoke)
    try:
        if adapter == 'code':
            with pytest.raises(ValueError, match='connection'):
                codes.fill(target, 'Q!7&z=R9', time.monotonic() + 20)
        else:
            secret = dict(card_number='4242424242424242', exp_month='12', exp_year='2031', cvc='123')
            backend = SimpleNamespace(needs_unlock=False, get_meta=lambda _: SimpleNamespace(label='Synthetic'), resolve_secret=lambda _: secret.copy())
            monkeypatch.setattr(pf, 'payment_backend', lambda *a: backend)
            monkeypatch.setattr('tools.browser_vault_tool._confirm_payment_fill', lambda *a: True)
            assert pf.approved_fill(target, 'vault_test', lambda: None)['status'] == 'unknown'
        assert reached and not commands
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
        assert nested.sup._page_session_id == previous
    finally:
        nested.sup._ws = old_ws
        (codes.release if adapter == 'code' else pf.release)(target)
        other.close()


@pytest.mark.parametrize('consume', [False, True])
def test_private_payment_idle_expiry_preserves_live_lease(nested, tmp_path, monkeypatch, consume):
    from secure_env_ingress.parent_session import ParentSession
    payment_page(nested)
    other, previous = wrongsite(nested)
    authorize(tmp_path, monkeypatch, nested.sup, nested.parent)
    separate = ParentSession(nested.sup, nested.parent)
    original, found = pf.discover, []
    def discover(*args):
        found.extend(replace(t, expires=time.monotonic() + .4) for t in original(*args))
        return found
    monkeypatch.setattr(pf, 'discover', discover)
    picker, selected = pf.PaymentSelection(), None
    try:
        _, response = picker.choose('scope', nested.sup.task_id, nested.parent, 'https://parent.test', 'vault_test')
        assert len(response['candidates']) == 2
        if consume:
            selected, _ = picker.choose('scope', nested.sup.task_id, nested.parent, 'https://parent.test', 'vault_test', response['candidates'][0]['selection'])
        deadline = time.monotonic() + 3
        while picker._entries:
            assert time.monotonic() < deadline
            time.sleep(.02)
        # Empty entries alone are not the timer's completion barrier: _drop
        # pops before synchronous remote disposal. Wait for its critical section
        # before asserting completed cleanup, without another choose() call.
        with picker._lock:
            assert not picker._entries
            assert found[0].parent_session.closed == (not consume)
        # Timer releases only the abandoned sibling, not the actively held choice.
        assert separate.check() == separate.sid
        if selected:
            pf.release(selected)
            selected = None
        assert found[0].parent_session.closed
        with pytest.raises(Exception):
            codes._call(nested.sup, 'Target.getTargetInfo', {}, found[0].parent_sid)
        assert separate.check() == separate.sid
        assert nested.sup._page_session_id == previous
    finally:
        if selected:
            pf.release(selected)
        picker.close()
        separate.drop(None)
        other.close()
