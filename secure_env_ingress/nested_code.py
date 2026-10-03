"""Bounded, explicit-parent OTP traversal with retained isolated-world authority.

Only synthetic/public metadata leaves discovery. No card adapter expansion.
"""
from dataclasses import dataclass, field
import json
import secrets
import threading
import time

from .code_targets import CodeTarget, _call, _classified, _supervisor
from .vault_ingress import strict_origin


# Deliberately conservative: any mutation of a captured document is sticky.
# The closure, not a page-editable stamp, is the retained-node authority.
_GUARD = r'''function(nodes, inspection=false) {
  const doc=document, href=location.href, origin=self.origin;
  const path=e=>{const p=[];for(;e;e=e.parentNode)p.push(e);return p};
  const attrs=e=>JSON.stringify(Array.from(e.attributes||[],a=>[a.name,a.value]));
  const saved=nodes.map(e=>({e,path:path(e),attrs:attrs(e),form:e.form,
    formAttrs:e.form?attrs(e.form):null}));
  let bad=false, closed=false;
  const historyLength=history.length;
  if(!self.navigation)throw Error('unsupported navigation authority');
  const dirty=()=>{bad=true};
  navigation.addEventListener('navigate',dirty);
  addEventListener('popstate',dirty);addEventListener('hashchange',dirty);
  const filled=new Map();
  const observer=new MutationObserver(r=>{if(r.length)bad=true});
  observer.observe(doc,{subtree:true,childList:true,attributes:true,characterData:true});
  const valid=()=>{
    if(observer.takeRecords().length)bad=true;
    if(Array.from(filled).some(([i,v])=>saved[i].e.value!==v))bad=true;
    return !bad&&!closed&&document===doc&&self.origin===origin&&location.href===href&&history.length===historyLength&&
      saved.every(s=>s.e.isConnected&&s.e.ownerDocument===doc&&attrs(s.e)===s.attrs&&
        path(s.e).length===s.path.length&&path(s.e).every((n,i)=>n===s.path[i])&&
        s.e.form===s.form&&(!s.form||(s.form.isConnected&&attrs(s.form)===s.formAttrs))&&
        (inspection||(!s.e.disabled&&!s.e.readOnly&&s.e.getClientRects().length&&
        getComputedStyle(s.e).display!=='none'&&getComputedStyle(s.e).visibility==='visible')));
  };
  return Object.freeze({document:doc,valid,close(){closed=true;observer.disconnect();navigation.removeEventListener('navigate',dirty);
    removeEventListener('popstate',dirty);removeEventListener('hashchange',dirty);filled.clear();saved.length=0;nodes.length=0},
    focus(i){if(!valid())return false;saved[i].e.focus();return valid()&&doc.hasFocus()&&doc.activeElement===saved[i].e},
    write(i,value){if(!valid()||!doc.hasFocus()||doc.activeElement!==saved[i].e)return {written:false,valid:false};
      const e=saved[i].e;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
      filled.set(i,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));
      return {written:true,valid:valid()&&doc.hasFocus()&&doc.activeElement===e};}
  });
}'''


def _result(response):
    payload = response.get('result', {})
    if 'error' in response or 'exceptionDetails' in payload:
        raise ValueError('nested context refused')
    return payload.get('result', {})


def _invoke(sup, sid, obj, function, args=(), by_value=True):
    return _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': obj,
        'functionDeclaration': function, 'arguments': [{'value': x} for x in args],
        'returnByValue': by_value}, sid))


def _parent(sup, parent):
    sid = sup._page_session_id
    if (not isinstance(parent, str) or not 1 <= len(parent) <= 100 or not sid
            or _call(sup, 'Target.getTargetInfo', {}, sid)['result']['targetInfo']['targetId'] != parent):
        raise ValueError('task-selected parent mismatch')
    return sid


class _Lease:
    def __init__(self, sup):
        self.sup, self.objects, self.sessions, self.refs = sup, [], [], 0
        self.released = set()
        self.resources = {}
        self.lock = threading.Lock()
        self.closed = False

    def keep(self, sid, obj):
        self.objects.append((sid, obj))
        return obj

    def discard(self, sid, obj):
        try:
            _invoke(self.sup, sid, obj, 'function(){if(this.close)this.close();return true}')
        except Exception:
            pass
        try:
            _call(self.sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
        except Exception:
            pass
        if (sid, obj) in self.objects:
            self.objects.remove((sid, obj))

    def prune(self):
        live_objects = set().union(*(v[0] for v in self.resources.values())) if self.resources else set()
        live_sessions = set().union(*(v[1] for v in self.resources.values())) if self.resources else set()
        for sid, obj in list(reversed(self.objects)):
            if (sid, obj) not in live_objects:
                self.discard(sid, obj)
        for sid in list(reversed(self.sessions)):
            if sid not in live_sessions:
                try:
                    _call(self.sup, 'Target.detachFromTarget', {'sessionId': sid})
                except Exception:
                    pass
                self.sessions.remove(sid)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.resources.clear()
        self.prune()


@dataclass(frozen=True)
class NestedCodeTarget(CodeTarget):
    parent: str = ''
    frame: str = ''
    parent_sid: str = field(default='', repr=False)
    leaf_sid: str = field(default='', repr=False)
    leaf_guard: str = field(default='', repr=False)
    # (containing session, containing frame, child frame, exact backend owner, guard)
    ancestry: tuple = field(default=(), repr=False)
    lease: object = field(default=None, repr=False, compare=False)
    expires: float = 0


def _context(sup, sid, frame, lease):
    params = {'frameId': frame, 'worldName': 'secure-code-' + secrets.token_hex(12)}
    try:
        probe = _call(sup, 'Page.createIsolatedWorld', params, sid)
    except RuntimeError as exc:
        if 'No frame for given id found' not in str(exc):
            raise
        probe = {}
    if not probe.get('result', {}).get('executionContextId'):
        sid = _call(sup, 'Target.attachToTarget', {'targetId': frame, 'flatten': True})['result']['sessionId']
        lease.sessions.append(sid)
        probe = _call(sup, 'Page.createIsolatedWorld', params, sid)
    return sid, probe['result']['executionContextId']


def _eval(sup, sid, context, expression, by_value=False):
    return _result(_call(sup, 'Runtime.evaluate', {'expression': expression,
        'contextId': context, 'returnByValue': by_value}, sid))


def _document_capacity(sup, sid, context=None, doc=None):
    if doc is None:
        doc = _eval(sup, sid, context, 'document')['objectId']
    try:
        root = _call(sup, 'DOM.describeNode', {'objectId': doc, 'depth': 16, 'pierce': True}, sid)['result']['node']
        pending, count = [root], 0
        while pending:
            node = pending.pop()
            count += 1
            if count > 2000 or any(s.get('shadowRootType') != 'user-agent' for s in node.get('shadowRoots', [])):
                raise ValueError('unsupported shadow or document capacity')
            children = node.get('children', [])
            if node.get('childNodeCount', 0) > len(children):
                raise ValueError('unsupported document depth')
            pending.extend(children)
    finally:
        _call(sup, 'Runtime.releaseObject', {'objectId': doc}, sid)


def discover(origin, label, task, parent):
    from agent.vault_login_classifier import build_inspection_js
    sup = _supervisor(task)
    psid = _parent(sup, parent)
    root = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
    lease = _Lease(sup)
    targets, visited = [], set()
    deadline = time.monotonic() + 120

    def visit(sid, frame, ancestry, depth):
        if time.monotonic() >= deadline or depth > 8 or frame in visited or len(visited) >= 40:
            raise ValueError('nested traversal capacity')
        visited.add(frame)
        sid, context = _context(sup, sid, frame, lease)
        actual = _eval(sup, sid, context, 'self.origin', True).get('value')
        strict_origin(actual)  # Opaque/sandbox/non-HTTPS ancestors are unsupported.
        capacity = _eval(sup, sid, context, '(() => {const all=document.querySelectorAll("*");return all.length<=2000&&!Array.from(all).some(e=>e.shadowRoot)})()', True).get('value')
        if capacity is not True:
            raise ValueError('unsupported document')
        _document_capacity(sup, sid, context)
        if depth and actual == origin:
            nonce = secrets.token_hex(12)
            inspector = lease.keep(sid, _eval(sup, sid, context,
                '(() => {const raw=' + build_inspection_js(nonce) + ';const nodes=Array.from(document.querySelectorAll("input,select"));const guard=(' + _GUARD + ')(nodes,true);return {raw,nodes,href:location.href,guard,close(){guard.close()}}})()')['objectId'])
            raw = _invoke(sup, sid, inspector, 'function(){return this.raw}').get('value')
            if not isinstance(raw, str) or len(raw) > 100000:
                raise ValueError('inspection capacity')
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > 200:
                raise ValueError('control capacity')
            groups = {}
            for c in _classified(rows):
                groups.setdefault(c.control.form_index, []).append(c)
            for controls in groups.values():
                controls.sort(key=lambda c: c.control.index)
                if len(controls) > 1 and not (4 <= len(controls) <= 16
                        and all(c.control.max_length == 1 for c in controls)
                        and all(b.control.index == a.control.index + 1 for a, b in zip(controls, controls[1:]))):
                    raise ValueError('ambiguous code form')
                if len(targets) >= 20:
                    raise ValueError('candidate capacity')
                if _invoke(sup, sid, inspector, 'function(){return this.guard.valid()}').get('value') is not True:
                    raise ValueError('inspection changed')
                guard = lease.keep(sid, _invoke(sup, sid, inspector,
                    'function(indices){if(!this.guard.valid())throw Error();return (' + _GUARD + ')(indices.map(i=>this.nodes[i]))}',
                    ([c.control.index for c in controls],), False)['objectId'])
                href = _invoke(sup, sid, inspector, 'function(){return this.href}').get('value')
                targets.append(NestedCodeTarget(origin, label, task, parent, nonce, href,
                    tuple(controls), sup, parent, frame, psid, sid, guard, ancestry, lease,
                    time.monotonic() + 240))
        owners = lease.keep(sid, _eval(sup, sid, context, 'Array.from(document.querySelectorAll("iframe,frame"))')['objectId'])
        count = _invoke(sup, sid, owners, 'function(){return this.length}').get('value')
        if not isinstance(count, int) or count > 20:
            raise ValueError('frame capacity')
        for i in range(count):
            owner_obj = lease.keep(sid, _invoke(sup, sid, owners, 'function(i){return this[i]}', (i,), False)['objectId'])
            node = _call(sup, 'DOM.describeNode', {'objectId': owner_obj}, sid)['result']['node']
            child, owner = node.get('frameId'), node['backendNodeId']
            if not child or _call(sup, 'DOM.getFrameOwner', {'frameId': child}, sid)['result']['backendNodeId'] != owner:
                raise ValueError('orphan frame')
            guard = lease.keep(sid, _invoke(sup, sid, owner_obj,
                'function(){if(this.hasAttribute("sandbox")&&!this.sandbox.contains("allow-same-origin"))throw Error();return (' + _GUARD + ')([this])}', (), False)['objectId'])
            visit(sid, child, ancestry + ((sid, frame, child, owner, guard),), depth + 1)

    try:
        visit(psid, root, (), 0)
        lease.refs = len(targets)
        for target in targets:
            assert_target(target)
            lease.resources[target.leaf_guard] = (
                {(target.leaf_sid, target.leaf_guard)} | {(a[0], a[4]) for a in target.ancestry},
                {target.parent_sid, target.leaf_sid} | {a[0] for a in target.ancestry})
        lease.prune()  # Inspection/temporary node arrays are no longer authorities.
        if not targets:
            lease.close()
        return targets
    except BaseException:
        lease.close()
        raise


def assert_target(target):
    sup = _supervisor(target.task)
    if (sup is not target.supervisor or target.lease.closed or time.monotonic() >= target.expires
            or _parent(sup, target.parent) != target.parent_sid):
        raise ValueError('stale nested target')
    for sid, frame, child, owner, guard in target.ancestry:
        if _call(sup, 'DOM.getFrameOwner', {'frameId': child}, sid)['result']['backendNodeId'] != owner:
            raise ValueError('frame owner changed')
        if _invoke(sup, sid, guard, 'function(){return this.valid()}').get('value') is not True:
            raise ValueError('ancestor changed')
        doc = _invoke(sup, sid, guard, 'function(){return this.document}', (), False)['objectId']
        _document_capacity(sup, sid, doc=doc)
    if _invoke(sup, target.leaf_sid, target.leaf_guard, 'function(){return this.valid()}').get('value') is not True:
        raise ValueError('code document changed')
    doc = _invoke(sup, target.leaf_sid, target.leaf_guard, 'function(){return this.document}', (), False)['objectId']
    _document_capacity(sup, target.leaf_sid, doc=doc)


def fill(target, code, expires_at):
    from agent.vault_login_classifier import build_otp_fills
    from agent.redact import register_vault_redaction_value
    register_vault_redaction_value(code)
    fills = build_otp_fills(list(target.controls), code)
    if not fills or len(fills) != len(target.controls):
        raise ValueError('invalid code fields')
    maximum = target.controls[0].control.max_length
    if len(fills) == 1 and maximum is not None and maximum < len(code):
        raise ValueError('code too long')
    for i, f in enumerate(fills):
        if time.monotonic() >= expires_at:
            return False
        assert_target(target)
        if _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                'function(i){return this.focus(i)}', (i,)).get('value') is not True:
            return False
        assert_target(target)
        if time.monotonic() >= expires_at:
            return False
        result = _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
            'function(i,v){return this.write(i,v)}', (i, f['value'])).get('value')
        if not isinstance(result, dict) or result != {'written': True, 'valid': True}:
            return False
        assert_target(target)
    return True


def release(target):
    with target.lease.lock:
        if not target.lease.closed and target.leaf_guard not in target.lease.released:
            target.lease.released.add(target.leaf_guard)
            if target.lease.resources:
                target.lease.resources.pop(target.leaf_guard, None)
                target.lease.prune()
            else:
                # Also supports partial discovery/test targets without a resource map.
                for sid, obj in list(target.lease.objects):
                    if obj == target.leaf_guard:
                        target.lease.discard(sid, obj)
            target.lease.refs -= 1
            if target.lease.refs <= 0:
                target.lease.close()
