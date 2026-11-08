"""Plugin-only retained password and origin-bound native TOTP filling.

Passwords use the native LOGIN classifier, never OTP semantics/value policies.
Only metadata/handles enter this API; secret resolution has no native-fill fallback.
"""
from dataclasses import dataclass
import json
import time

from .bound_cdp import dispatch_scope
from .vault_ingress import strict_origin
from .native_fill import BOUNDARY_JS


def login_backend(handle, origin):
    """Metadata-origin gate MUST precede every resolver, including TOTP."""
    from agent.vault_backends import backend_for_handle
    strict_origin(origin)
    backend = backend_for_handle(handle)
    if backend is None:
        raise ValueError('login backend unavailable')
    # No manager unlock bypass. The native unlock tool owns masked prompting.
    if backend.needs_unlock and not backend.is_unlocked():
        raise ValueError('unlock required')
    meta = backend.get_meta(handle)
    if meta is None or meta.kind != 'login':
        raise ValueError('login metadata unavailable')
    allowed = tuple(meta.allowed_origins) or ((str(meta.origin),) if meta.origin else ())
    if origin not in allowed:
        raise ValueError('login origin mismatch')
    return backend, meta


# Native stamp/origin/type policy in the plugin's retained isolated context.
# Only counts/verdicts leave the write; no secret readback to Python.

GUARD_JS = r'''function(roots, selected=null){
 let boundary=(''' + BOUNDARY_JS + r''')(roots,selected?[selected]:[],true);
 return {document,valid:()=>boundary.valid(),
  bind(e){boundary.close();boundary=(''' + BOUNDARY_JS + r''')(roots,[e],true);return boundary.valid()},
  close(){boundary.close()},write(v){return boundary.write(0,v)}};
}'''


@dataclass(frozen=True)
class LoginTarget:
    origin: str
    parent_sid: str
    supervisor: object
    lease: object
    guards: tuple
    ancestry: tuple
    destination: tuple
    expires: float


def discover(task, parent, origin, guard, field_selector=None, frame=None):
    from . import nested_code as nc
    from .code_targets import _supervisor, _call
    from .parent_session import ParentSession
    from .exact_code import EXPORT_JS, selector
    from agent.vault_login_classifier import LoginControl, classify_login_control
    strict_origin(origin)
    if field_selector is not None:
        selector(field_selector)
    ps = ParentSession(_supervisor(task), parent)
    lease = None
    try:
        ps.transport.scope_guard = guard
        sup, sid = ps.transport, ps.sid
        lease = nc._Lease(sup)
        lease.parent_session = ps
        guards, ancestry, candidates, visited = [], [], [], set()
        deadline = time.monotonic() + 120
        root = _call(sup, 'Page.getFrameTree', {}, sid)['result']['frameTree']['frame']['id']
        def visit(sid, fid, depth, chain=(), lineage=()):
            if depth > 8 or fid in visited or len(visited) >= 40 or time.monotonic() >= deadline:
                raise ValueError('login traversal capacity')
            visited.add(fid)
            sid, context = nc._context(sup, sid, fid, lease)
            actual = nc._eval(sup, sid, context, 'location.origin', True).get('value')
            https_document=True
            try:
                strict_origin(actual)
            except ValueError:
                if fid==root:
                    raise
                https_document=False
            shadows = nc._shadow_roots(sup, sid, context)
            roots = lease.keep(sid, nc._eval(sup, sid, context, '[document]')['objectId'])
            for backend in shadows:
                obj = lease.keep(sid, _call(sup, 'DOM.resolveNode', {'backendNodeId': backend,'executionContextId': context}, sid)['result']['object']['objectId'])
                nc._result(_call(sup, 'Runtime.callFunctionOn', {'objectId':roots,'functionDeclaration':'function(r){this.push(r)}','arguments':[{'objectId':obj}]}, sid))
            # Only selected destination/ancestor documents remain fill authority.
            dg = lease.keep(sid, nc._invoke(sup,sid,roots,'function(){return ('+GUARD_JS+')(this.slice())}',(),False)['objectId'])
            guards.append((sid,dg,shadows))
            # Non-HTTPS ancestors are traversal/lineage only, never destinations.
            if https_document and actual == origin and (frame is None or frame == fid or frame == 'top' and fid == root):
                inspect = lease.keep(sid,nc._invoke(sup,sid,roots,'function(){return ('+EXPORT_JS+')(this.slice(),"input")}',(),False)['objectId'])
                raw = nc._invoke(sup,sid,inspect,'function(){return JSON.stringify(this.rows)}').get('value')
                if not isinstance(raw,str):
                    raise ValueError('login inspection capacity')
                rows=json.loads(raw)
                for row in rows:
                    c=classify_login_control(LoginControl.from_dict(row))
                    if c is None or c.token!='current-password':
                        continue
                    obj=lease.keep(sid,nc._invoke(sup,sid,inspect,'function(i){return this.nodes[i]}',(row['index'],),False)['objectId'])
                    if field_selector is not None and nc._invoke(sup,sid,obj,'function(s){return this.matches(s)}',(field_selector,)).get('value') is not True:
                        continue
                    # Native score then traversal/DOM order; descriptors only narrow discovery.
                    candidates.append((sid,dg,obj,chain,c.score,lineage))
            # Native inspection selects within the requested document first.
            # Nested lookup extends an empty parent; unrelated frames are not
            # a refusal census once a destination (or explicit top) is selected.
            if candidates or frame == 'top':
                return
            owners=lease.keep(sid,nc._invoke(sup,sid,roots,'function(){return this.flatMap(r=>Array.from(r.querySelectorAll("iframe,frame")))}',(),False)['objectId'])
            count=nc._invoke(sup,sid,owners,'function(){return this.length}').get('value')
            if type(count) is not int or count>20:
                raise ValueError('login frame capacity')
            for i in range(count):
                obj=lease.keep(sid,nc._invoke(sup,sid,owners,'function(i){return this[i]}',(i,),False)['objectId'])
                node=_call(sup,'DOM.describeNode',{'objectId':obj},sid)['result']['node']
                child,owner=node.get('frameId'),node['backendNodeId']
                if not child or _call(sup,'DOM.getFrameOwner',{'frameId':child},sid)['result']['backendNodeId']!=owner:
                    raise ValueError('login frame owner changed')
                ancestry.append((sid,child,owner))
                visit(sid,child,depth+1,chain+((sid,dg,obj),),lineage+((sid,child,owner),))
                if candidates:
                    return
        visit(sid,root,0)
        if not candidates:
            raise ValueError('no login target')
        sid,dg,obj,chain,_,selected_ancestry=max(candidates,key=lambda c:c[4])
        response=_call(sup,'Runtime.callFunctionOn',{'objectId':dg,
            'functionDeclaration':'function(e){return this.bind(e)}',
            'arguments':[{'objectId':obj}], 'returnByValue':True},sid)
        if nc._result(response).get('value') is not True:
            raise ValueError('login binding refused')
        selected_guards={(sid,dg)}|{(s,g) for s,g,_ in chain}
        target=LoginTarget(origin,ps.sid,sup,lease,tuple(g for g in guards if g[:2] in selected_guards),selected_ancestry,(sid,dg),deadline)
        assert_target(target)
        return target
    except BaseException:
        if lease is not None:
            lease.close()
        else:
            ps.drop(None)
        raise


def assert_target(target):
    from .code_targets import _call
    from . import nested_code as nc
    if target.lease.closed or time.monotonic()>=target.expires or target.lease.parent_session.check()!=target.parent_sid:
        raise ValueError('stale login target')
    for sid,child,owner in target.ancestry:
        if _call(target.supervisor,'DOM.getFrameOwner',{'frameId':child},sid)['result']['backendNodeId']!=owner:
            raise ValueError('login frame changed')
    for sid,obj,_ in target.guards:
        if nc._invoke(target.supervisor,sid,obj,'function(){return this.valid()}').get('value') is not True:
            raise ValueError('login destination changed')



def fill_login(target, handle, guard):
    from .redaction_compat import register_context_secret
    from .nested_code import _invoke
    started=False
    password=None
    try:
        with dispatch_scope(target.expires):
            guard()
            backend,_=login_backend(handle,target.origin)
            assert_target(target)
            # Resolve only after exact destination and frozen human/session admission.
            guard()
            target.supervisor.check()
            login_backend(handle,target.origin)
            password=backend.resolve_password(handle)
            if not isinstance(password,str) or not password:
                raise ValueError('password unavailable')
            register_context_secret(password,kind='secret')
            guard()
            assert_target(target)
            login_backend(handle,target.origin)
            sid,obj=target.destination
            started=True
            result=_invoke(target.supervisor,sid,obj,'function(v){return this.write(v)}',(password,)).get('value')
            if result!={'written':True,'valid':True}:
                raise ValueError('login write unconfirmed')
            guard()
            return {'success':True,'status':'filled','kind':'login','origin':target.origin,'filled_fields':1}
    except Exception:
        return {'success':False,'status':'unknown' if started else 'target_refused'}
    finally:
        password=None


def fill_totp(target, handle, guard):
    from . import code_targets as ct
    from .redaction_compat import register_context_secret
    from .bound_cdp import fill_diagnostic_scope
    code=None
    diagnostic={'writes_attempted':0}
    try:
        with dispatch_scope(target.expires), fill_diagnostic_scope() as diagnostic:
            guard()
            backend,_=login_backend(handle,target.origin)
            ct.assert_target(target)
            guard()
            target.supervisor.check()
            login_backend(handle,target.origin)
            code=backend.resolve_otp(handle)
            if not isinstance(code,str) or not code:
                return {'success':False,'status':'otp_unavailable'}
            register_context_secret(code,kind='otp')
            guard()
            ct.assert_target(target)
            login_backend(handle,target.origin)
            # Saved-provider OTPs use native selection directly. The human
            # transient-code entry contract (length/charset/purpose) is separate.
            from . import nested_code
            if not nested_code.fill(target,code,target.expires):
                raise ValueError('otp unconfirmed')
            return {'success':True,'status':'filled','kind':'totp','origin':target.origin}
    except Exception:
        return {'success':False,'status':'unknown' if diagnostic['writes_attempted'] else 'target_refused'}
    finally:
        code=None
