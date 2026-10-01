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


@dataclass(frozen=True)
class PaymentTarget:
    task: str
    parent: str
    frame: str
    origin: str
    form_index: int | None
    controls: tuple = field(repr=False)
    owner_node: int
    supervisor: object = field(repr=False, compare=False)
    parent_sid: str = field(repr=False)
    child_sid: str = field(repr=False)
    parent_guard: str = field(repr=False)
    child_guard: str = field(repr=False)
    expires: float
    attachment: object = field(default=None, repr=False, compare=False)


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


# MutationObserver.takeRecords closes the observer-microtask gap. Conservatively
# any DOM mutation invalidates this document capability, even if later reverted.
# References, all attributes, ancestor topology, form identity/action and URL are
# retained in closures in an isolated world, inaccessible to ordinary page JS.
_GUARD = r'''function(nodes, inspection=false) {
  const doc=document, href=location.href, origin=self.origin;
  const chain=e => { const a=[]; for(;e;e=e.parentNode) a.push(e); return a; };
  const attrs=e => e.attributes ? JSON.stringify(Array.from(e.attributes,a=>[a.name,a.value])) : '';
  const snapshots=nodes.map(e=>({e, path:chain(e), form:e.form,
    formPath:e.form ? chain(e.form) : [], attributes:attrs(e),
    formAttrs:e.form ? attrs(e.form) : ''}));
  let changed=false;
  const observer=new MutationObserver(() => {changed=true;});
  observer.observe(doc,{subtree:true,childList:true,attributes:true,characterData:true});
  const equal=(a,b)=>a.length===b.length && a.every((e,i)=>e===b[i]);
  const valid=()=> {
    if(observer.takeRecords().length) changed=true;
    return !changed && document===doc && location.href===href && self.origin===origin &&
      snapshots.every(s => s.e.isConnected && equal(chain(s.e),s.path) &&
        attrs(s.e)===s.attributes && s.e.form===s.form &&
        (!s.form || (s.form.isConnected && attrs(s.form)===s.formAttrs && equal(chain(s.form),s.formPath))) &&
        (inspection || (!s.e.disabled && !s.e.readOnly && s.e.getClientRects().length &&
        getComputedStyle(s.e).visibility==='visible' && getComputedStyle(s.e).display!=='none')));
  };
  const inputSetter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  const selectSetter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set;
  return Object.freeze({valid, close:()=>observer.disconnect(),
    focus:i=>{if(!valid()) return false; nodes[i].focus(); return valid() && doc.hasFocus() && doc.activeElement===nodes[i];},
    accepts:(i,v,token)=>{const e=nodes[i]; return valid() &&
      (token!=='cc-exp' || (e.type!=='number' && (!e.placeholder || /^mm\/yy$/i.test(e.placeholder.replace(/\s/g,''))))) &&
      (e.tagName==='SELECT' ? Array.from(e.options).filter(o=>o.value===v && !o.disabled && (!o.parentElement || !o.parentElement.disabled)).length===1 :
      (['text','tel','password','number'].includes(e.type) && (e.maxLength<0 || v.length<=e.maxLength) &&
       (!e.pattern || new RegExp('^(?:'+e.pattern+')$','u').test(v))));},
    write:(i,v)=>{if(!valid() || !doc.hasFocus() || doc.activeElement!==nodes[i]) return {written:false,valid:false}; const e=nodes[i];
      (e.tagName==='SELECT' ? selectSetter : inputSetter).call(e,v);
      const exact=e.value===v;
      e.dispatchEvent(new Event('input',{bubbles:true}));
      if(!valid()) return {written:true,valid:false};
      e.dispatchEvent(new Event('change',{bubbles:true}));
      return {written:true,valid:valid() && exact && e.value===v};}
  });
}'''


def _remote_guard(sup, sid, frame, indices=None, owner=None):
    context = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
        'worldName': 'secure-payment-' + secrets.token_hex(12)}, sid)['result']['executionContextId']
    if owner is not None:
        obj = _call(sup, 'DOM.resolveNode', {'backendNodeId': owner, 'executionContextId': context}, sid)['result']['object']['objectId']
        result = _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': obj,
            'functionDeclaration': 'function(){return (' + _GUARD + ')([this]);}'}, sid))
        _call(sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
    else:
        expression = '(' + _GUARD + ')(' + json.dumps(indices) + '.map(i=>document.querySelectorAll("input,select")[i]))'
        result = _result(_call(sup, 'Runtime.evaluate', {'expression': expression, 'contextId': context}, sid))
    if not result.get('objectId'):
        raise ValueError('guard unavailable')
    return result['objectId']


def validate_group(controls):
    tokens = [c.token for c in controls]
    required = {'cc-number', 'cc-csc'}
    expiry = {'cc-exp'} if 'cc-exp' in tokens else {'cc-exp-month', 'cc-exp-year'}
    if (len(set(tokens)) != len(tokens) or not required | expiry <= set(tokens)
            or ('cc-exp' in tokens and {'cc-exp-month', 'cc-exp-year'} & set(tokens))):
        raise ValueError('ambiguous payment form')


def mapped_fills(controls, secret):
    from agent.vault_login_classifier import select_checkout_fills
    from agent.vault_store import PAYMENT_FIELDS
    validate_group(controls)
    fills = select_checkout_fills(list(controls), secret, PAYMENT_FIELDS)
    if len(fills) != len(controls):
        raise ValueError('missing saved field')
    return sorted(fills, key=lambda f: f['index'])


def payment_backend(handle, origin):
    from agent.vault_backends import backend_for_handle
    strict_origin(origin)
    if not isinstance(handle, str) or not handle.startswith('vault_') or len(handle) > 100:
        raise ValueError('native payment handle required')
    backend = backend_for_handle(handle)
    if backend is None or backend.needs_unlock:
        raise ValueError('native payment required')
    meta = backend.get_meta(handle)
    if meta is None or meta.kind != 'payment' or meta.origin != origin:
        raise ValueError('payment origin mismatch')
    return backend


def _parent(sup, parent):
    sid = sup._page_session_id
    if not sid or _call(sup, 'Target.getTargetInfo', {}, sid)['result']['targetInfo']['targetId'] != parent:
        raise ValueError('explicit parent is not task-selected supervisor page')
    return sid


def discover(task, parent, origin):
    """DOM owners prove lineage: parent's frame tree omits Chromium OOPIFs."""
    from agent.vault_login_classifier import LoginControl, classify_checkout_control, build_inspection_js
    strict_origin(origin)
    sup = _supervisor(task)
    psid = _parent(sup, parent)
    root_frame = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
    root = _call(sup, 'DOM.getDocument', {'depth': 0}, psid)['result']['root']['nodeId']
    owners = _call(sup, 'DOM.querySelectorAll', {'nodeId': root, 'selector': 'iframe,frame'}, psid)['result']['nodeIds']
    if len(owners) > 20:
        raise ValueError('too many frames')
    targets = []
    deadline = time.monotonic() + 120
    try:
        for owner_id in owners:
            node = _call(sup, 'DOM.describeNode', {'nodeId': owner_id, 'depth': 0}, psid)['result']['node']
            frame, owner = node.get('frameId'), node['backendNodeId']
            if not frame:
                raise ValueError('frame unavailable')
            csid, attachment, inspector = psid, None, None
            try:
                try:
                    probe = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
                        'worldName': 'secure-payment-inspect-' + secrets.token_hex(12)}, psid)
                except RuntimeError as error:
                    if 'No frame for given id found' not in str(error):
                        raise
                    probe = {}
                if probe.get('error') or not probe.get('result', {}).get('executionContextId'):
                    csid = _call(sup, 'Target.attachToTarget', {'targetId': frame, 'flatten': True})['result']['sessionId']
                    attachment = _Attachment(sup, csid)
                    probe = _call(sup, 'Page.createIsolatedWorld', {'frameId': frame,
                        'worldName': 'secure-payment-inspect-' + secrets.token_hex(12)}, csid)
                context = probe['result']['executionContextId']
                origin_now = _result(_call(sup, 'Runtime.evaluate', {'expression': 'self.origin',
                    'contextId': context, 'returnByValue': True}, csid)).get('value')
                if origin_now != origin:
                    continue
                # Inspection and exact node-reference capture are one evaluation.
                expression = '(() => { const raw=' + build_inspection_js(secrets.token_hex(12)) + '; const nodes=Array.from(document.querySelectorAll("input,select")); return {raw,nodes,guard:(' + _GUARD + ')(nodes,true)}; })()'
                inspector = _result(_call(sup, 'Runtime.evaluate', {'expression': expression, 'contextId': context}, csid))['objectId']
                raw = _invoke(sup, csid, inspector, 'function(){return this.raw;}')
                if not isinstance(raw, str) or len(raw) > 100000:
                    raise ValueError('inspection capacity')
                rows = json.loads(raw)
                if not isinstance(rows, list) or len(rows) > 200:
                    raise ValueError('too many controls')
                groups = {}
                for row in rows:
                    c = classify_checkout_control(LoginControl.from_dict(row))
                    if c and c.token in {'cc-number', 'cc-name', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc', 'postal-code'}:
                        groups.setdefault(c.control.form_index, []).append(c)
                for form, controls in groups.items():
                    validate_group(controls)
                    if len(targets) >= 20:
                        raise ValueError('too many forms')
                    pg, cg = None, None
                    try:
                        if _call(sup, 'DOM.getFrameOwner', {'frameId': frame}, psid)['result']['backendNodeId'] != owner:
                            raise ValueError('owner changed')
                        pg = _remote_guard(sup, psid, root_frame, owner=owner)
                        indices = [c.control.index for c in controls]
                        cg = _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': inspector,
                            'functionDeclaration': 'function(indices){if(!this.guard.valid())throw Error(); return (' + _GUARD + ')(indices.map(i=>this.nodes[i]));}',
                            'arguments': [{'value': indices}]}, csid))['objectId']
                        if attachment:
                            attachment.objects.add(cg)
                        t = PaymentTarget(task, parent, frame, origin, form, tuple(controls), owner,
                            sup, psid, csid, pg, cg, deadline, attachment)
                        targets.append(t)
                        assert_target(t)
                    except BaseException:
                        if pg:
                            _invoke(sup, psid, pg, 'function(){this.close();return true;}')
                            _call(sup, 'Runtime.releaseObject', {'objectId': pg}, psid)
                        raise
            finally:
                if inspector:
                    try:
                        _invoke(sup, csid, inspector, 'function(){this.guard.close();return true;}')
                        _call(sup, 'Runtime.releaseObject', {'objectId': inspector}, csid)
                    except Exception:
                        pass
                if attachment and not attachment.objects:
                    attachment.drop(None)
        return targets
    except BaseException:
        for t in targets:
            release(t)
        raise


def assert_target(target):
    sup = _supervisor(target.task)
    if sup is not target.supervisor or time.monotonic() >= target.expires or _parent(sup, target.parent) != target.parent_sid:
        raise ValueError('stale target')
    # getFrameOwner resolves only in the selected parent document's session;
    # the exact remote owner/document closures reject detach and reparenting.
    if _call(sup, 'DOM.getFrameOwner', {'frameId': target.frame}, target.parent_sid)['result']['backendNodeId'] != target.owner_node:
        raise ValueError('frame lineage changed')
    for sid, obj in ((target.parent_sid, target.parent_guard), (target.child_sid, target.child_guard)):
        if _invoke(sup, sid, obj, 'function(){return this.valid();}') is not True:
            raise ValueError('document changed')


def release(target):
    for sid, obj in ((target.parent_sid, target.parent_guard), (target.child_sid, target.child_guard)):
        try:
            _invoke(target.supervisor, sid, obj, 'function(){this.close(); return true;}')
            _call(target.supervisor, 'Runtime.releaseObject', {'objectId': obj}, sid)
        except Exception:
            pass
    if target.attachment is not None:
        target.attachment.drop(target.child_guard)


def approved_fill(target, handle, scope_guard):
    from tools.browser_vault_tool import _confirm_payment_fill, _bot_desktop_browser_session
    from agent.redact import register_vault_redaction_value
    started = False
    secret = None
    try:
        scope_guard()
        backend = payment_backend(handle, target.origin)
        meta = backend.get_meta(handle)
        assert_target(target)
        if not _confirm_payment_fill(meta.label, target.origin):
            return {'success': False, 'status': 'payment_declined'}
        scope_guard()
        assert_target(target)
        approved_meta = meta
        backend = payment_backend(handle, target.origin)
        if backend.get_meta(handle) != approved_meta:
            raise ValueError('payment metadata changed')
        secret = backend.resolve_secret(handle)
        fills = mapped_fills(target.controls, secret)
        for value in secret.values():
            register_vault_redaction_value(value)
        # Register derived expiry as well as raw fields before page contact.
        for f in fills:
            register_vault_redaction_value(f['value'])
        sup, sid, obj = target.supervisor, target.child_sid, target.child_guard
        for i, f in enumerate(fills):
            if _invoke(sup, sid, obj, 'function(i,v,token){return this.accepts(i,v,token);}', (i, f['value'], f['token'])) is not True:
                raise ValueError('unsupported field format')
        filled = 0
        for i, f in enumerate(fills):
            scope_guard()
            assert_target(target)
            if _bot_desktop_browser_session(target.task):
                from tools.bot_desktop import lease
                lease.assert_agent_may_act()
            if _invoke(sup, sid, obj, 'function(i){return this.focus(i);}', (i,)) is not True:
                raise ValueError('focus mutated target')
            # Focus callbacks in either document complete before the next CDP
            # read. Recheck BOTH lineage and closure identities before each write.
            scope_guard()
            assert_target(target)
            if _bot_desktop_browser_session(target.task):
                from tools.bot_desktop import lease
                lease.assert_agent_may_act()
            started = True
            result = _invoke(sup, sid, obj, 'function(i,v){return this.write(i,v);}', (i, f['value']))
            if not isinstance(result, dict) or not result.get('written') or not result.get('valid'):
                raise ValueError('write not confirmed')
            filled += 1
            scope_guard()
            assert_target(target)
        return {'success': True, 'status': 'filled', 'filled_fields': filled, 'origin': target.origin, 'kind': 'payment'}
    except Exception:
        return {'success': False, 'status': 'unknown' if started else 'target_refused'}
    finally:
        if secret is not None:
            secret.clear()


class PaymentSelection:
    def __init__(self):
        self._entries = {}
        self._lock = threading.RLock()

    def _drop(self, keys):
        for k in list(keys):
            _, _, _, target = self._entries.pop(k)
            release(target)

    def choose(self, scope, task, parent, origin, handle, selection=None):
        with self._lock:
            now = time.monotonic()
            self._drop([k for k, v in self._entries.items() if v[0] <= now])
            binding = (task, parent, origin, handle)
            if selection is not None:
                entry = self._entries.get(selection)
                if entry is None or entry[1:3] != (scope, binding):
                    raise ValueError('invalid selection')
                self._entries.pop(selection)
                target = entry[3]
                try:
                    assert_target(target)
                except BaseException:
                    release(target)
                    raise
                return target, None
            self._drop([k for k, v in self._entries.items() if v[1] == scope])
            targets = discover(task, parent, origin)
            if len(targets) == 1:
                return targets[0], None
            if not targets:
                return None, {'success': False, 'status': 'no_payment_frame'}
            if len(self._entries) + len(targets) > 128:
                for t in targets:
                    release(t)
                raise ValueError('selection capacity')
            candidates = []
            for t in targets:
                token = secrets.token_urlsafe(24)
                self._entries[token] = (min(now + 120, t.expires), scope, binding, t)
                candidates.append({'selection': token, 'parent': t.parent, 'frame': t.frame,
                    'origin': t.origin, 'form_index': t.form_index})
            return None, {'success': False, 'status': 'selection_required', 'candidates': candidates}

    def close(self):
        with self._lock:
            self._drop(list(self._entries))
