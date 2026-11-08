"""Exact task-selected payment iframe fill over native supervisor WS only.

No page search, endpoint/selector/JS arguments, manager unlock, or submission.
Direct child frames only. Remote closure guards retain real DOM identities in an
isolated world; no mutable page stamps are used as authority. CDP failures after
starting a write are unknown, never represented as zero writes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import threading
import time

from .code_targets import _call, _supervisor
from .vault_ingress import strict_origin
from .native_fill import BOUNDARY_JS
from .bound_cdp import BoundCDP, FrameUnavailable


@dataclass(frozen=True)
class PaymentTarget:
    task: str
    parent: str
    frame: str
    origin: str
    form_index: int | None
    controls: tuple = field(repr=False)
    owner_node: int | None
    supervisor: object = field(repr=False, compare=False)
    parent_sid: str = field(repr=False)
    child_sid: str = field(repr=False)
    parent_guard: str = field(repr=False)
    child_guard: str = field(repr=False)
    expires: float
    attachment: object = field(default=None, repr=False, compare=False)
    parent_session: object = field(default=None, repr=False, compare=False)


class _Attachment:
    """Shared transport lifetime, not shared selection authority."""
    def __init__(self, sup, sid):
        self.sup, self.sid = sup, sid
        self.objects = set()
        self.lock = threading.Lock()
        self.closed = False

    def drop(self, obj):
        with self.lock:
            self.objects.discard(obj)
            if not self.objects and not self.closed:
                self.closed = True
                try:
                    if isinstance(self.sup, BoundCDP):
                        self.sup.dispose(self.sid, wait=True)
                    else:
                        _call(self.sup, 'Target.detachFromTarget', {'sessionId': self.sid})
                except Exception:
                    pass



def _result(response):
    payload = response.get('result', {})
    if 'error' in response or 'exceptionDetails' in payload:
        raise ValueError('browser refused')
    return payload.get('result', {})


def _invoke(sup, sid, obj, function, args=()):
    return _result(_call(sup, 'Runtime.callFunctionOn', {
        'objectId': obj, 'functionDeclaration': function,
        'arguments': [{'value': v} for v in args], 'returnByValue': True}, sid)).get('value')


# Native selection stamps in retained parent contexts; no presentation locks.

_GUARD = r'''function(nodes, inspection=false, owner=false){
 const boundary=(''' + BOUNDARY_JS + r''')([document],inspection||owner?[]:nodes);
 const slots=nodes.map(e=>e.getAttribute('data-hermes-vault-slot'));
 return {...boundary,prepare(fills,resume){
  if(!boundary.valid())return false;
  if(!resume)return [];
  const adopted=[];
  for(let i=0;i<fills.length;i++){const f=fills[i],node=document.querySelector('[data-hermes-vault-slot="'+slots[f.slot]+'"]');if(!node)return false;const value=node.value;if(value){
   const matches=f.token==='cc-number'?/^[0-9]+(?: [0-9]+)*$/.test(value)&&value.replaceAll(' ','')===f.value:value===f.value;
   if(!matches)return false;adopted.push(i);
  }}
  return adopted;
 }};
}'''


def _remote_guard(sup, sid, frame, indices=None, owner=None):
    context = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
        'worldName': 'secure-payment-' + secrets.token_hex(12)}, sid)['result']['executionContextId']
    if owner is not None:
        obj = _call(sup, 'DOM.resolveNode', {'backendNodeId': owner, 'executionContextId': context}, sid)['result']['object']['objectId']
        result = _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': obj,
            'functionDeclaration': 'function(){return (' + _GUARD + ')([this],false,true);}'}, sid))
        _call(sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
    else:
        expression = '(' + _GUARD + ')(' + json.dumps(indices) + '.map(i=>document.querySelectorAll("input,select")[i]))'
        result = _result(_call(sup, 'Runtime.evaluate', {'expression': expression, 'contextId': context}, sid))
    if not result.get('objectId'):
        raise ValueError('guard unavailable')
    return result['objectId']


def classify_payment_control(control):
    from agent.vault_login_classifier import classify_checkout_control
    return classify_checkout_control(control)


def mapped_fills(controls, secret):
    from agent.vault_login_classifier import select_checkout_fills
    from agent.vault_store import PAYMENT_FIELDS
    fills=select_checkout_fills(list(controls),secret,PAYMENT_FIELDS)
    if not fills:
        raise ValueError('no saved payment fields')
    return sorted(fills,key=lambda f:f['index'])


def payment_backend(handle, origin):
    from agent.vault_backends import backend_for_handle
    strict_origin(origin)
    backend = backend_for_handle(handle)
    if backend is None or backend.needs_unlock and not backend.is_unlocked():
        raise ValueError('unlock required')
    meta = backend.get_meta(handle)
    allowed=tuple(meta.allowed_origins) or ((str(meta.origin),) if meta.origin else ()) if meta else ()
    if meta is None or meta.kind != 'payment' or origin not in allowed:
        raise ValueError('payment origin mismatch')
    return backend


def _parent(sup, parent):
    sid = sup.page_session_id
    if not sid or _call(sup, 'Target.getTargetInfo', {}, sid)['result']['targetInfo']['targetId'] != parent:
        raise ValueError('explicit parent is not task-selected supervisor page')
    return sid


def discover(task, parent, origin):
    """DOM owners prove lineage: parent's frame tree omits Chromium OOPIFs."""
    from agent.vault_login_classifier import LoginControl, build_inspection_js
    strict_origin(origin)
    sup = _supervisor(task)
    from .parent_session import ParentSession
    parent_session = ParentSession(sup, parent)
    sup = parent_session.transport
    psid = parent_session.sid
    targets = []
    deadline = time.monotonic() + 120
    try:
        root_frame = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
        def frames():
            yield root_frame, None
            root = _call(sup,'DOM.getDocument',{'depth':0},psid)['result']['root']['nodeId']
            owners = _call(sup,'DOM.querySelectorAll',{'nodeId':root,'selector':'iframe,frame'},psid)['result']['nodeIds']
            if len(owners)>20:
                raise ValueError('too many frames')
            for owner_id in owners:
                node=_call(sup,'DOM.describeNode',{'nodeId':owner_id,'depth':0},psid)['result']['node']
                if not node.get('frameId'):
                    raise ValueError('frame unavailable')
                yield node['frameId'],node['backendNodeId']
        for frame,owner in frames():
            csid, attachment, inspector = psid, None, None
            try:
                try:
                    probe = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
                        'worldName': 'secure-payment-inspect-' + secrets.token_hex(12)}, psid)
                except FrameUnavailable:
                    probe = {}
                if probe.get('error') or not probe.get('result', {}).get('executionContextId'):
                    csid = _call(sup, 'Target.attachToTarget', {'targetId': frame, 'flatten': True})['result']['sessionId']
                    attachment = _Attachment(sup, csid)
                    probe = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
                        'worldName': 'secure-payment-inspect-' + secrets.token_hex(12)}, csid)
                context = probe['result']['executionContextId']
                origin_now = _result(_call(sup, 'Runtime.evaluate', {'expression': 'location.origin',
                    'contextId': context, 'returnByValue': True}, csid)).get('value')
                if origin_now != origin:
                    continue
                # Inspection and exact node-reference capture are one evaluation.
                nonce=secrets.token_hex(12)
                expression = ('(() => { const nonce='+json.dumps(nonce)+'; const raw='+build_inspection_js(nonce)+
                    '; const nodes=Array.from(document.querySelectorAll("input,select"));const guard=('+_GUARD+')(nodes,true);'+
                    'const close=guard.close;guard.close=()=>{close();for(const e of nodes)if((e.getAttribute("data-hermes-vault-slot")||"").startsWith(nonce+":"))e.removeAttribute("data-hermes-vault-slot")};'+
                    'return {raw,nodes,guard}; })()')
                inspector = _result(_call(sup, 'Runtime.evaluate', {'expression': expression, 'contextId': context}, csid))['objectId']
                raw = _invoke(sup, csid, inspector, 'function(){return this.raw;}')
                if not isinstance(raw, str):
                    raise ValueError('inspection capacity')
                rows = json.loads(raw)
                if not isinstance(rows, list):
                    raise ValueError('too many controls')
                groups = {}
                for row in rows:
                    c = classify_payment_control(LoginControl.from_dict(row))
                    if c and c.token in {'cc-number', 'cc-name', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'postal-code'}:
                        groups.setdefault(None, []).append(c)
                for form, controls in groups.items():
                    if len(targets) >= 20:
                        raise ValueError('too many forms')
                    pg, cg = None, None
                    try:
                        if owner is not None and _call(sup, 'DOM.getFrameOwner', {'frameId': frame}, psid)['result']['backendNodeId'] != owner:
                            raise ValueError('owner changed')
                        pg = _remote_guard(sup, psid, root_frame, indices=[], owner=owner)
                        indices = [c.control.index for c in controls]
                        cg = _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': inspector,
                            'functionDeclaration': 'function(indices){if(!this.guard.valid())throw Error(); return (' + _GUARD + ')(indices.map(i=>this.nodes[i]));}',
                            'arguments': [{'value': indices}]}, csid))['objectId']
                        if attachment:
                            attachment.objects.add(cg)
                        t = PaymentTarget(task, parent, frame, origin, form, tuple(controls), owner,
                            sup, psid, csid, pg, cg, deadline, attachment, parent_session)
                        parent_session.keep(pg)
                        targets.append(t)
                        assert_target(t)
                    except BaseException:
                        if pg:
                            _close_object(sup, psid, pg)
                        raise
            finally:
                if inspector:
                    _close_object(sup, csid, inspector, inspection=True)
                if attachment and not attachment.objects:
                    attachment.drop(None)
            if frame == root_frame and targets:
                return targets
        return targets
    except BaseException:
        for t in targets:
            release(t)
        raise
    finally:
        parent_session.drop(None)


def assert_target(target):
    from .exact_card import CardTarget, assert_target as card_assert
    if isinstance(target, CardTarget):
        return card_assert(target)
    sup = target.supervisor
    parent_sid = target.parent_session.check() if target.parent_session is not None else _parent(sup, target.parent)
    if not target.supervisor.valid() or time.monotonic() >= target.expires or parent_sid != target.parent_sid:
        raise ValueError('stale target')
    sup = target.supervisor
    # getFrameOwner resolves only in the selected parent document's session;
    # the exact remote owner/document closures reject detach and reparenting.
    if target.owner_node is not None and _call(sup, 'DOM.getFrameOwner', {'frameId': target.frame}, target.parent_sid)['result']['backendNodeId'] != target.owner_node:
        raise ValueError('frame lineage changed')
    for sid, obj in ((target.parent_sid, target.parent_guard), (target.child_sid, target.child_guard)):
        if _invoke(sup, sid, obj, 'function(){return this.valid();}') is not True:
            raise ValueError('document changed')


def _close_object(sup, sid, obj, *, inspection=False):
    if isinstance(sup, BoundCDP):
        sup.close_object(sid, obj, inspection=inspection)
        return
    try:
        _invoke(sup, sid, obj, 'function(){this.guard.close();return true;}' if inspection else
                'function(){this.close();return true;}')
    except Exception:
        pass
    try:
        _call(sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
    except Exception:
        pass


def release(target):
    from .exact_card import CardTarget, release as card_release
    if isinstance(target, CardTarget):
        return card_release(target)
    for sid, obj in ((target.parent_sid, target.parent_guard), (target.child_sid, target.child_guard)):
        _close_object(target.supervisor, sid, obj)
    if target.attachment is not None:
        target.attachment.drop(target.child_guard)
    if target.parent_session is not None:
        target.parent_session.drop(target.parent_guard)


def approved_fill(target, handle, scope_guard, resume_existing=False):
    from .bound_cdp import dispatch_scope
    with dispatch_scope(target.expires):
        from .exact_card import CardTarget, approved_fill as card_fill
        if isinstance(target, CardTarget):
            if resume_existing:
                return {'success': False, 'status': 'target_refused', 'stage': 'preflight'}
            return card_fill(target, handle, scope_guard)
        from tools.browser_vault_tool import _confirm_payment_fill
        from agent.redact import register_vault_redaction_value
        started = False
        secret = None
        stage = 'preflight'
        try:
            scope_guard()
            backend = payment_backend(handle, target.origin)
            meta = backend.get_meta(handle)
            assert_target(target)
            stage = 'consent'
            merchant = target.parent_session.origin
            if not _confirm_payment_fill(meta.label, f'payment frame {target.origin}; merchant page {merchant}'):
                return {'success': False, 'status': 'payment_declined'}
            stage = 'revalidation'
            scope_guard()
            assert_target(target)
            backend = payment_backend(handle, target.origin)
            stage = 'mapping'
            secret = backend.resolve_secret(handle)
            fills = mapped_fills(target.controls, secret)
            for f in fills:
                f['slot']=next(i for i,c in enumerate(target.controls) if c.control.index==f['index'])
            # Mirror native Vault policy: payment metadata is not a global secret.
            register_vault_redaction_value(secret.get('card_number', ''))
            from .redaction_compat import register_context_secret
            register_context_secret(secret.get('cvc', ''), kind='cvc')
            sup, sid, obj = target.supervisor, target.child_sid, target.child_guard
            adopted=[]
            if resume_existing:
                stage='existing'
                adopted=_invoke(sup,sid,obj,'function(fills){return this.prepare(fills,true);}',(fills,))
                if not isinstance(adopted,list) or any(type(i) is not int or not 0<=i<len(fills) for i in adopted):
                    raise ValueError('existing field refused')
            filled = len(adopted)
            for i, f in enumerate(fills):
                if i in adopted:
                    continue
                scope_guard()
                assert_target(target)
                stage = 'write'
                started = True
                result = _invoke(sup, sid, obj, 'function(i,v,token){return this.write(i,v,token);}', (f['slot'], f['value'], f['token']))
                if not isinstance(result, dict) or result.get('valid') is not True:
                    raise ValueError('write not confirmed')
                if result.get('written') is True:
                    filled += 1
                scope_guard()
            if not filled:
                raise ValueError('no fields written')
            stage = 'completion'
            scope_guard()
            result = {'success': True, 'status': 'filled', 'filled_fields': filled, 'origin': target.origin, 'kind': 'payment'}
            if resume_existing:
                result['resumed_fields'] = len(adopted)
            return result
        except Exception:
            return {'success': False, 'status': 'unknown' if started else 'target_refused', 'stage': stage}
        finally:
            if secret is not None:
                secret.clear()


class PaymentSelection:
    def __init__(self):
        self._entries = {}
        self._lock = threading.RLock()
        self._timers = {}
        self._closed = False

    def _drop(self, keys):
        for k in list(keys):
            entry = self._entries.pop(k)
            release(entry[3])
        live = {entry[4] for entry in self._entries.values()}
        for batch in list(self._timers):
            if batch not in live:
                self._timers.pop(batch).cancel()

    def cancel_batch(self, batch):
        batch.set()  # Worker sees cancellation even before publication.
        with self._lock:
            self._drop([k for k, v in self._entries.items() if v[4] is batch])

    def _expire_batch(self, batch):
        with self._lock:
            self._drop([k for k, v in self._entries.items() if v[4] is batch])

    def choose(self, scope, task, parent, origin, handle, selection=None, *, batch=None, target_spec=None):
        from .bound_cdp import acquisition_scope
        if target_spec is not None:
            from .exact_card import validate_spec
            target_spec = validate_spec(target_spec, parent)
        batch = batch if batch is not None else threading.Event()
        with self._lock:
            if self._closed or batch.is_set():
                raise ValueError('selection stopped')
            now = time.monotonic()
            self._drop([k for k, v in self._entries.items() if v[0] <= now])
            binding = (task, parent, origin, handle)
            if target_spec is not None:
                binding += (json.dumps(target_spec, sort_keys=True),)
            if selection is not None:
                entry = self._entries.get(selection)
                if entry is None or entry[1:3] != (scope, binding):
                    raise ValueError('invalid selection')
                self._entries.pop(selection)
                self._drop([])
                target = entry[3]
                try:
                    assert_target(target)
                except BaseException:
                    release(target)
                    raise
                return target, None
        # Neither shutdown nor cancellation waits behind CDP discovery.
        with acquisition_scope(batch):
            if target_spec is None:
                targets = discover(task, parent, origin)
            else:
                from .exact_card import discover as card_discover
                targets = card_discover(task, parent, origin, target_spec)
        with self._lock:
            if self._closed or batch.is_set():
                for t in targets:
                    release(t)
                raise ValueError('selection stopped')
            if len(targets) == 1:
                return targets[0], None
            if not targets:
                return None, {'success': False, 'status': 'no_payment_frame'}
            self._drop([k for k, v in self._entries.items() if v[1] == scope])
            if len(self._entries) + len(targets) > 128:
                for t in targets:
                    release(t)
                raise ValueError('selection capacity')
            candidates = []
            deadline = min(time.monotonic() + 120, *(t.expires for t in targets))
            for t in targets:
                token = secrets.token_urlsafe(24)
                self._entries[token] = (deadline, scope, binding, t, batch)
                candidates.append({'selection': token, 'parent': t.parent, 'frame': t.frame,
                    'origin': t.origin, 'form_index': t.form_index})
            timer = threading.Timer(max(0, deadline - time.monotonic()), self._expire_batch, (batch,))
            timer.daemon = True
            self._timers[batch] = timer
            timer.start()
            return None, {'success': False, 'status': 'selection_required', 'candidates': candidates}

    def close(self):
        with self._lock:
            self._closed = True
            self._drop(list(self._entries))
