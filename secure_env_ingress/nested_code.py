"""Bounded, explicit-parent OTP traversal with retained isolated-world authority.

Only synthetic/public metadata leaves discovery. No card adapter expansion.
"""
from dataclasses import dataclass, field
import json
import secrets
import threading
import time

from .code_targets import CodeTarget, _call, _classified, _supervisor
from .bound_cdp import BoundCDP, FrameUnavailable
from .grouped_otp import GROUP_JS


# Retained context/parent lineage plus native selected-slot policy.
# Unrelated UI changes are not authority changes.
from .native_fill import BOUNDARY_JS

_GUARD = r'''function(nodes, inspection=false, roots=[document], selector=null, spec=null){
 const boundary=(''' + BOUNDARY_JS + r''')(roots,inspection?[]:nodes);
 return boundary;
}'''


def _result(response):
    payload = response.get('result', {})
    if 'error' in response or 'exceptionDetails' in payload:
        from .bound_cdp import fill_diagnostic
        fill_diagnostic(reason='cdp_error' if 'error' in response else 'context_refused')
        raise ValueError('nested context refused')
    return payload.get('result', {})


def _invoke(sup, sid, obj, function, args=(), by_value=True):
    try:
        response = _call(sup, 'Runtime.callFunctionOn', {'objectId': obj,
            'functionDeclaration': function, 'arguments': [{'value': x} for x in args],
            'returnByValue': by_value}, sid)
    except RuntimeError as exc:
        # Navigation destroys the retained world; normalize only that exact
        # refusal, never retry or resolve a replacement destination.
        if 'Cannot find context with specified id' not in str(exc):
            raise
        raise ValueError('nested context refused') from None
    return _result(response)


def _parent(sup, parent):
    sid = sup.page_session_id
    if (not isinstance(parent, str) or not 1 <= len(parent) <= 100 or not sid
            or _call(sup, 'Target.getTargetInfo', {}, sid)['result']['targetInfo']['targetId'] != parent):
        raise ValueError('task-selected parent mismatch')
    return sid


class _Lease:
    def __init__(self, sup):
        self.sup, self.objects, self.sessions, self.refs = sup, [], [], 0
        self.released = set()
        self.resources = {}
        self.contexts = {}
        self.lock = threading.Lock()
        self.closed = False
        self.parent_session = None

    def keep(self, sid, obj):
        self.objects.append((sid, obj))
        return obj

    def discard(self, sid, obj):
        if isinstance(self.sup, BoundCDP):
            self.sup.close_object(sid, obj)
            if (sid, obj) in self.objects:
                self.objects.remove((sid, obj))
            return
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
                    if isinstance(self.sup, BoundCDP):
                        self.sup.dispose(sid, wait=True)
                    else:
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
        if self.parent_session is not None:
            self.parent_session.drop(None)


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
    explicit_parent: bool = field(default=True, kw_only=True)


def _context(sup, sid, frame, lease):
    params = {'frameId': frame, 'worldName': 'secure-code-' + secrets.token_hex(12)}
    try:
        probe = _call(sup, 'Page.createIsolatedWorld', params, sid)
    except FrameUnavailable:
        probe = {}
    if not probe.get('result', {}).get('executionContextId'):
        sid = _call(sup, 'Target.attachToTarget', {'targetId': frame, 'flatten': True})['result']['sessionId']
        lease.sessions.append(sid)
        probe = _call(sup, 'Page.createIsolatedWorld', params, sid)
    return sid, probe['result']['executionContextId']


def _eval(sup, sid, context, expression, by_value=False):
    return _result(_call(sup, 'Runtime.evaluate', {'expression': expression,
        'contextId': context, 'returnByValue': by_value}, sid))


def _shadow_roots(sup, sid, context):
    """Discover closed roots once, without nesting the whole DOM in a CDP reply.

    Flat parent links are needed only to scope Shadow roots to this retained
    document, not to freeze a census or compare its subsequent mutations.
    """
    doc=_eval(sup,sid,context,'document')['objectId']
    try:
        bound=_call(sup,'DOM.describeNode',{'objectId':doc,'depth':0},sid)['result']['node']['backendNodeId']
        _call(sup,'DOM.enable',{},sid)
        nodes=_call(sup,'DOM.getFlattenedDocument',{'depth':-1,'pierce':True},sid)['result']['nodes']
        by_id={node['nodeId']:node for node in nodes}
        shadows=[]
        for host in nodes:
            for child in host.get('shadowRoots',[]):
                linked=dict(child,parentId=host['nodeId'])
                by_id[linked['nodeId']]=linked
                shadows.append(linked)
            if host.get('contentDocument'):
                document=host['contentDocument']
                by_id[document['nodeId']]=document
        def belongs(node):
            while node.get('nodeType')!=9:
                node=by_id.get(node.get('parentId'))
                if node is None:
                    return False
            return node.get('backendNodeId')==bound
        return tuple(dict.fromkeys(node['backendNodeId'] for node in shadows
            if node.get('shadowRootType') in ('open','closed') and belongs(node)))
    finally:
        _call(sup,'Runtime.releaseObject',{'objectId':doc},sid)


def _inspection_js(nonce, selector, generic=False, saved_otp=False):
    from .exact_code import EXPORT_JS
    # Legacy classifier indices exclude textarea/editing hosts, as before.
    controls = 'input,select,textarea,[contenteditable]' if generic else 'input,select'
    return 'function(){const roots=this.slice();const exported=(' + EXPORT_JS + ')(roots,' + json.dumps(controls) + ');const {nodes,rows}=exported;const selector=' + json.dumps(selector) + r''';
      const matches=selector===null?[]:roots.flatMap(r=>Array.from(r.querySelectorAll(selector)));
      for(const row of rows){
        const e=nodes[row.index];row.selected=matches.includes(e);
        if(''' + json.dumps(saved_otp) + r''')continue;
        const group=(''' + GROUP_JS + r''')(e);
        row.groupedOtp=group&&!group.forbidden?nodes.indexOf(group.digits[0]):null;
        row.groupForbidden=!!group?.forbidden;
        // Native split mapping consumes effective cell length, while retained
        // DOM attributes (including absent maxlength) remain exact authority.
        if(group&&!group.forbidden)row.maxLength=1;
        row.splitContainer=nodes.indexOf(Array.from(e.parentElement?.children||[]).find(n=>n.matches('input,select')));
        row.splitSize=group&&!group.forbidden?group.digits.length:Array.from(e.parentElement?.children||[]).filter(n=>n.matches('input')&&n.maxLength===1).length;
      }
      const raw=JSON.stringify(rows);const guard=(''' + _GUARD + r''')(nodes.slice(),true,roots.slice(),selector,null,''' + json.dumps(generic) + r''');
      return {raw,rows,nodes,roots,selector,matchCount:matches.length,href:location.href,guard,close(){guard.close()}};
    }'''



def discover(origin, label, task, parent, field_selector=None, *, target_spec=None, saved_otp=False):
    from .code_targets import validate_field_selector
    validate_field_selector(field_selector, parent)
    sup = _supervisor(task)
    from .parent_session import ParentSession
    parent_session = ParentSession(sup, parent)
    sup = parent_session.transport
    psid = parent_session.sid
    lease = _Lease(sup)
    lease.parent_session = parent_session
    targets, visited = [], set()
    selector_matches = []
    deadline = time.monotonic() + 120

    def visit(sid, frame, ancestry, depth):
        if time.monotonic() >= deadline or depth > 8 or frame in visited or len(visited) >= 40:
            raise ValueError('nested traversal capacity')
        visited.add(frame)
        sid, context = _context(sup, sid, frame, lease)
        actual = _eval(sup, sid, context, 'location.origin', True).get('value')
        shadows = _shadow_roots(sup, sid, context)
        roots = lease.keep(sid, _eval(sup, sid, context, '[document]')['objectId'])
        for backend in shadows:
            obj = lease.keep(sid, _call(sup, 'DOM.resolveNode', {'backendNodeId': backend, 'executionContextId': context}, sid)['result']['object']['objectId'])
            _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': roots, 'functionDeclaration': 'function(root){this.push(root)}', 'arguments': [{'objectId': obj}], 'returnByValue': True}, sid))
        if actual == origin:
            nonce = secrets.token_hex(12)
            inspector = lease.keep(sid, _invoke(sup, sid, roots,
                _inspection_js(nonce, field_selector, generic=target_spec is not None, saved_otp=saved_otp), (), False)['objectId'])
            raw = _invoke(sup, sid, inspector, 'function(){return this.raw}').get('value')
            if not isinstance(raw, str):
                raise ValueError('inspection capacity')
            rows = json.loads(raw)
            if not isinstance(rows, list):
                raise ValueError('control capacity')
            if field_selector is not None or target_spec is not None:
                selector_matches.append(_invoke(sup, sid, inspector, 'function(){return this.matchCount}').get('value'))
            groups = {}
            root_indices = {r['index']: r['rootIndex'] for r in rows}
            rows_by_index = {r['index']: r for r in rows}
            selected_groups = set()
            if target_spec is not None:
                from .exact_code import RESOLVE_JS
                from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl
                resolved = _invoke(sup, sid, inspector, RESOLVE_JS, (target_spec,)).get('value')
                classified = [] if resolved is None else [ClassifiedLoginControl(LoginControl.from_dict(r), 100, 'one-time-code') for r in resolved['rows']]
            elif saved_otp:
                from agent.vault_login_classifier import LoginControl, classify_otp_controls
                classified=classify_otp_controls([LoginControl.from_dict(r) for r in rows if field_selector is None or r.get('selected')])
            else:
                selected_groups = {r.get('groupedOtp') for r in rows
                                   if r.get('selected') and r.get('groupedOtp') is not None}
                if field_selector is not None and selected_groups:
                    # A uniquely matched cell hints its already-proven retained group;
                    # the hint is never independent OTP evidence or a new destination.
                    classified = [c for c in _classified(rows)
                                  if rows_by_index[c.control.index].get('groupedOtp') in selected_groups]
                else:
                    classified = _classified(rows, explicit=True) if field_selector is not None else _classified(rows)
            for c in classified:
                groups.setdefault(('exact',) if target_spec is not None or saved_otp else (root_indices[c.control.index], c.control.form_index), []).append(c)
            for controls in groups.values():
                if target_spec is None and not saved_otp:
                    witnesses={rows_by_index[c.control.index].get('groupedOtp') for c in controls}
                    if any(w is not None for w in witnesses) and len(witnesses)!=1:
                        raise ValueError('ambiguous code form')
                    if len(controls)>1 and len({rows_by_index[c.control.index].get('splitContainer') for c in controls})!=1:
                        raise ValueError('ambiguous code form')
                    if len(controls)>1 and any(rows_by_index[c.control.index].get('splitSize')!=len(controls) for c in controls):
                        raise ValueError('ambiguous code form')
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
                    'function(indices,spec){if(!this.guard.valid())throw Error();return (' + _GUARD + ')(indices.map(i=>this.nodes[i]),false,this.roots.slice(),this.selector,spec,!!spec)}',
                    ([c.control.index for c in controls], target_spec), False)['objectId'])
                lease.contexts[guard] = context
                href = _invoke(sup, sid, inspector, 'function(){return this.href}').get('value')
                targets.append(NestedCodeTarget(origin, label, task, parent, nonce, href,
                    tuple(controls), sup, parent, frame, psid, sid, guard, ancestry, lease,
                    time.monotonic() + 240, field_selector=field_selector, target_spec=target_spec, explicit_parent=True))
        if saved_otp and targets:
            return
        owners = lease.keep(sid, _invoke(sup, sid, roots, 'function(){return this.flatMap(r=>Array.from(r.querySelectorAll("iframe,frame")))}', (), False)['objectId'])
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
                'function(){return (' + _GUARD + ')([this],false,[document,this.getRootNode()].filter((r,i,a)=>a.indexOf(r)===i),null,null,' + json.dumps(target_spec is not None) + ')}', (), False)['objectId'])
            lease.contexts[guard] = context
            visit(sid,child,ancestry+((sid,frame,child,owner,guard),),depth+1)
            if saved_otp and targets:
                return

    try:
        root = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
        visit(psid, root, (), 0)
        if field_selector is not None:
            if sum(selector_matches) > 1:
                raise ValueError('ambiguous code selector')
            if sum(selector_matches) != 1 or len(targets) != 1:
                raise ValueError('inadmissible code selector')
        if target_spec is not None and len(targets) != 1:
            raise ValueError("ambiguous exact target")
        lease.refs = len(targets)
        for target in targets:
            assert_target(target)
            lease.resources[target.leaf_guard] = (
                {(target.leaf_sid,target.leaf_guard)}|{(a[0],a[4]) for a in target.ancestry},
                {target.parent_sid,target.leaf_sid}|{a[0] for a in target.ancestry})
        lease.prune()  # Inspection/temporary node arrays are no longer authorities.
        if not targets:
            lease.close()
        return targets
    except BaseException:
        lease.close()
        raise



def assert_target(target):
    # The original capture already pins supervisor/task/profile validity; do not
    # acquire a second capture at every barrier or substitute another handle.
    sup = target.supervisor
    if (not sup.valid() or target.lease.closed or time.monotonic() >= target.expires
            or (target.lease.parent_session.check() if target.lease.parent_session is not None
                else _parent(sup, target.parent)) != target.parent_sid):
        raise ValueError('stale nested target')
    sup = target.supervisor
    checked = set()
    guards, requests, owners = [], [], []
    ancestors = list(target.ancestry)
    for sid, frame, child, owner, guard in ancestors:
        if (sid, guard) in checked:
            continue
        checked.add((sid, guard))
        owners.append((len(requests), owner))
        requests.append(('DOM.getFrameOwner', {'frameId': child}, sid))
        guards.append((sid, guard))
    if (target.leaf_sid, target.leaf_guard) not in checked:
        guards.append((target.leaf_sid, target.leaf_guard))
    for index,owner in owners:
        if _call(sup,*requests[index])['result']['backendNodeId']!=owner:
            raise ValueError('frame owner changed')
    for sid,obj in guards:
        if _invoke(sup,sid,obj,'function(){return this.valid()}').get('value') is not True:
            raise ValueError('code destination changed')


def fill(target, code, expires_at):
    from .bound_cdp import dispatch_scope
    with dispatch_scope(min(expires_at, target.expires)):
        from agent.vault_login_classifier import build_otp_fills
        from .redaction_compat import register_context_secret
        register_context_secret(code, kind='otp')
        if not target.controls:
            raise ValueError('invalid code fields')
        if time.monotonic() >= min(expires_at, target.expires):
            from .bound_cdp import fill_diagnostic
            fill_diagnostic(reason='expired')
            return False
        target_spec = getattr(target, 'target_spec', None)
        if target_spec is not None:
            from .exact_code import policy
            if not policy(target_spec).accepts(code):
                raise ValueError('invalid code')
            values = [code] if target_spec['layout'] == 'single' else list(code)
            fills = [{'value': value} for value in values]
        else:
            fills = build_otp_fills(list(target.controls), code)
        if not fills:
            raise ValueError('invalid code fields')
        from .bound_cdp import fill_diagnostic
        fill_diagnostic('revalidate', 'guard_refused')
        written = 0
        for ordinal, f in enumerate(fills):
            i = ordinal if target_spec is not None else next(j for j,c in enumerate(target.controls) if c.control.index==f['index'])
            if time.monotonic() >= expires_at:
                fill_diagnostic(reason='expired')
                return False
            assert_target(target)
            fill_diagnostic('write', 'write_unconfirmed')
            result = _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                'function(i,v){return this.write(i,v)}', (i, f['value'])).get('value')
            fill_diagnostic('readback', 'write_unconfirmed',
                            confirmed=isinstance(result, dict) and result.get('written') is True)
            if not isinstance(result, dict) or result.get('valid') is not True:
                return False
            if result.get('written') is True:
                written += 1
            elif target_spec is not None:
                return False  # A declared layout requires every requested cell.
        return written > 0


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
