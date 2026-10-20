"""Plugin-only retained password and origin-bound native TOTP filling.

Passwords use the native LOGIN classifier, never OTP semantics/value policies.
Only metadata/handles enter this API; secret resolution has no native-fill fallback.
"""
from dataclasses import dataclass
import json
import re
import time

from .bound_cdp import dispatch_scope
from .vault_ingress import strict_origin


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
    if meta is None or meta.kind != 'login' or meta.id != handle:
        raise ValueError('login metadata unavailable')
    allowed = tuple(meta.allowed_origins) or ((str(meta.origin),) if meta.origin else ())
    if origin not in allowed:
        raise ValueError('login origin mismatch')
    return backend, meta


# Isolated-world closure: retained originals, composed ancestry, sticky history,
# effective form association/action and a complete original control/root census.
# No DOM stamps, no fill-time selector lookup and no secret readback to Python.
GUARD_JS = r'''function(roots, selected=null){
 const doc=document,href=location.href,origin=self.origin;
 const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
 const census=query('input,select,textarea,button,form,iframe,frame,[contenteditable]');
 const path=e=>{let a=[];for(;e;e=e.parentNode||(e instanceof ShadowRoot?e.host:null))a.push(e);return a};
 const attrs=e=>JSON.stringify(Array.from(e.attributes||[]).map(a=>[a.name,a.value]));
 // One document authority owns both census and dispatch; no second observer can
 // mistake its own bounded transaction for an unrelated waiting mutation.
 let transaction=null,dynamic=true;
 let changes=new Map(),reconcileUsed=false;
 const visible=e=>{for(const p of path(e).filter(p=>p.nodeType===1)){const s=getComputedStyle(p);if(p.inert||p.hidden||p.getAttribute('aria-hidden')==='true'||p.getAttribute('aria-disabled')==='true'||s.display==='none'||s.visibility!=='visible'||s.contentVisibility==='hidden'||Number(s.opacity)===0)return false}return !!e.getClientRects().length};
 const visibleOwners=[];
 let cssComplex=false;
 const css=()=>{let out=[];const walk=rules=>{for(const r of rules){if(r.selectorText&&/\[|:has\(|:is\(|:not\(|:where\(/.test(r.selectorText))cssComplex=true;
   // Scope roots can make a nominally harmless state class hide a label.
   // Unsupported scope dependencies are not an own-dispatch exception.
   if(r.type===CSSRule.IMPORT_RULE||/^@scope(?:\s|\()/.test(r.cssText))cssComplex=true;
   if(r.selectorText&&/\.(?:is-)?(?:focused|focus|filled|valid|invalid|error|touched|dirty)\b/.test(r.selectorText)&&Array.from(r.style||[]).some(k=>!/^(?:color|background-color|border(?:-(?:top|right|bottom|left))?-color|outline-color|box-shadow|caret-color|text-decoration-color)$/.test(k)))cssComplex=true;
   out.push(r.cssText);if(r.cssRules)walk(r.cssRules)}};for(const root of roots){for(const sheet of [...Array.from(root.styleSheets||[]),...Array.from(root.adoptedStyleSheets||[])])walk(sheet.cssRules)}return JSON.stringify(out)};
 let originalCSS;try{originalCSS=css()}catch{originalCSS=null}
 // Unknown relational/attribute dependencies remain unsupported for dynamic
 // acknowledgement, not a blanket exception to semantic/history checks.
 const independent=()=>originalCSS!==null&&css()===originalCSS&&!cssComplex;
 const accepted=new Map();
 const admit=(m,next,reconciled=false)=>{
  if(!transaction||!selected||!dynamic||!independent())return false;
  const e=m.target,k=m.attributeName;
  if(reconciled)return true;
  let counts=changes.get(e);if(!counts){counts=new Map();changes.set(e,counts)}
  const count=(counts.get(k)||0)+1;counts.set(k,count);
  if(count>2||count>1&&m.oldValue!==next)return false;
  if(k==='value')return transaction==='write'&&e===selected&&next===expected;
  if(k==='aria-invalid')return e===selected&&['true','false'].includes(next);
  if(k==='class'&&(e===selected||path(selected).includes(e))){
   const before=(m.oldValue||'').split(/\s+/).filter(Boolean),after=(next||'').split(/\s+/).filter(Boolean);
   return before.every(x=>after.includes(x))&&after.filter(x=>!before.includes(x)).every(x=>/^(?:is-)?(?:focused|focus|filled|valid|invalid|error|touched|dirty)$/.test(x));
  }
  if(k==='disabled'&&transaction==='write'&&e.localName==='button'&&e.form===selected.form&&selected.form&&e.type==='submit'&&m.oldValue!==null&&next===null)return true;
  return false;
 };
 const protectedNodes=new Set(),labels=new Set();
 for(const e of census){for(const p of path(e))protectedNodes.add(p);
  for(const l of [...Array.from(e.labels||[]),...(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>e.getRootNode().getElementById(id)).filter(Boolean)]){
   labels.add(l);for(const p of path(l))protectedNodes.add(p);for(const p of l.querySelectorAll('*'))protectedNodes.add(p);
  }
 }
 const snapshots=census.map(e=>({e,path:path(e),attrs:attrs(e),form:e.form,action:e.form?.action,method:e.form?.method,value:e.value}));
 const rootHosts=roots.filter(r=>r instanceof ShadowRoot).map(r=>[r,r.host,path(r.host)]);
 let bad=false,closed=false,expected=selected?.value;
 if(!self.navigation)throw Error('unsupported navigation authority');
 const dirty=()=>{bad=true};
 // Observe actual input/change boundaries in each retained original root.
 // A restored final value does not erase an event-observable account change.
 // Closed-shadow roots are observed directly without relying on retargeting.
 const accountEvents=['beforeinput','input','change'];
 const accountSources=snapshots.filter(s=>s.e.matches('input,select,textarea'));
 const accountEvent=()=>{if(accountSources.some(s=>s.e!==selected&&s.e.value!==s.value))bad=true};
 for(const root of roots)for(const name of accountEvents)root.addEventListener(name,accountEvent,true);
 navigation.addEventListener('navigate',dirty);
 navigation.addEventListener('currententrychange',dirty);
 addEventListener('popstate',dirty);addEventListener('hashchange',dirty);
 const containsControl=n=>n.nodeType===1&&(n.matches('input,select,textarea,button,form,iframe,frame,base,style,link,[contenteditable]')||n.localName.includes('-')||n.querySelector('input,select,textarea,button,form,iframe,frame,base,style,link,[contenteditable]'));
 const consume=records=>{if(records.length>256){bad=true;return}
  // Exact public React input updater only: original password name -> empty,
  // password -> password, empty -> original name. No OTP type/name policy.
  const semantic=records.filter(m=>m.type==='attributes'&&m.target===selected&&['name','type'].includes(m.attributeName));
  const original=snapshots.find(s=>s.e===selected);
  const name=original&&JSON.parse(original.attrs).find(a=>a[0]==='name')?.[1];
  const reconciled=transaction==='write'&&!reconcileUsed&&name&&semantic.length===3&&
   semantic[0].attributeName==='name'&&semantic[0].oldValue===name&&
   semantic[1].attributeName==='type'&&semantic[1].oldValue==='password'&&
   semantic[2].attributeName==='name'&&semantic[2].oldValue===''&&
   selected.getAttribute('name')===name&&selected.getAttribute('type')==='password';
  if(reconciled)reconcileUsed=true;
  for(let i=0;i<records.length;i++){const m=records[i];
  if(m.type==='attributes'){
   if(protectedNodes.has(m.target)||m.target.matches('base,style,link')){
    const later=records.slice(i+1).find(n=>n.type==='attributes'&&n.target===m.target&&n.attributeName===m.attributeName);
    const next=later?later.oldValue:m.target.getAttribute(m.attributeName);
    if(!admit(m,next,reconciled&&semantic.includes(m)))bad=true;
    else accepted.set(m.target,attrs(m.target));
   }
  }else if(m.type==='characterData'){
   if(protectedNodes.has(m.target.parentNode)||m.target.parentElement?.closest('style'))bad=true;
  }else{
   if([...m.addedNodes,...m.removedNodes].some(n=>protectedNodes.has(n)||containsControl(n)||[...protectedNodes].some(p=>n.contains?.(p))))bad=true;
   if([...labels].some(l=>l===m.target||l.contains(m.target)))bad=true;
  }
 }};
 const observers=roots.map(r=>{const o=new MutationObserver(consume);o.observe(r,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true});return o});
 const same=(a,b)=>a.length===b.length&&a.every((e,i)=>e===b[i]);
 const live=()=>{
  observers.forEach(o=>consume(o.takeRecords()));
  if(closed||bad||doc!==document||href!==location.href||origin!==self.origin||!same(census,query('input,select,textarea,button,form,iframe,frame,[contenteditable]')))return false;
  if(rootHosts.some(([r,h,p])=>!h.isConnected||r.host!==h||!same(p,path(h))))return false;
  if(snapshots.some(s=>!s.e.isConnected||!same(s.path,path(s.e))||attrs(s.e)!==(accepted.get(s.e)||s.attrs)||s.e.form!==s.form||s.e.form?.action!==s.action||s.e.form?.method!==s.method||(s.e!==selected&&s.e.value!==s.value)))return false;
  if(visibleOwners.some(e=>!e.isConnected||!visible(e)))return false;
  if(selected){
   if(selected.value!==expected||selected.matches(':disabled')||selected.readOnly||selected.getAttribute('aria-disabled')==='true'||selected.getAttribute('aria-readonly')==='true')return false;
   for(const e of path(selected).filter(e=>e.nodeType===1)){const s=getComputedStyle(e);if(e.inert||e.getAttribute('aria-hidden')==='true'||e.getAttribute('aria-disabled')==='true'||s.display==='none'||s.visibility!=='visible'||s.contentVisibility==='hidden'||Number(s.opacity)===0)return false}
   if(!selected.getClientRects().length)return false;
  }
  return true;
 };
 const focused=()=>{let e=doc.activeElement;for(let i=0;i<roots.length;i++){const r=roots.find(r=>r instanceof ShadowRoot&&r.host===e);if(!r?.activeElement)break;e=r.activeElement}return e===selected&&doc.hasFocus()};
 const run=(kind,fn)=>{if(!live())return false;transaction=kind;changes=new Map();reconcileUsed=false;try{fn();observers.forEach(o=>consume(o.takeRecords()))}finally{transaction=null}return live()&&focused()};
 return {document:doc,valid:live,
  bind(e,d=true){if(selected||!census.includes(e)||!live())return false;selected=e;dynamic=d;expected=e.value;return live()},
  requireVisible(e){if(!census.includes(e)||!live())return false;visibleOwners.push(e);return live()},
  close(){closed=true;observers.forEach(o=>o.disconnect());for(const root of roots)for(const name of accountEvents)root.removeEventListener(name,accountEvent,true);navigation.removeEventListener('navigate',dirty);navigation.removeEventListener('currententrychange',dirty);removeEventListener('popstate',dirty);removeEventListener('hashchange',dirty)},
  focus(){if(!selected||!live())return false;return run('focus',()=>selected.focus())},
  write(value){if(!selected||!live()||!focused())return {written:false,valid:false};
   const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
   const valid=run('write',()=>{
    setter.call(selected,value);expected=value;
    selected.dispatchEvent(new Event('input',{bubbles:true,composed:true}));
    // Each event gets its own history/readback barrier; never dispatch change
    // through a destination invalidated by the preceding input handler.
    observers.forEach(o=>consume(o.takeRecords()));
    if(live()&&focused())selected.dispatchEvent(new Event('change',{bubbles:true,composed:true}));
   });
   return {written:true,valid};
  }
 };
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
        def visit(sid, fid, depth, chain=()):
            if depth > 8 or fid in visited or len(visited) >= 40 or time.monotonic() >= deadline:
                raise ValueError('login traversal capacity')
            visited.add(fid)
            sid, context = nc._context(sup, sid, fid, lease)
            actual = nc._eval(sup, sid, context, 'self.origin', True).get('value')
            https_document=True
            try:
                strict_origin(actual)
            except ValueError:
                if fid==root:
                    raise
                https_document=False
            shadows, _ = nc._document_capacity(sup, sid, context)
            roots = lease.keep(sid, nc._eval(sup, sid, context, '[document]')['objectId'])
            for backend in shadows:
                obj = lease.keep(sid, _call(sup, 'DOM.resolveNode', {'backendNodeId': backend,'executionContextId': context}, sid)['result']['object']['objectId'])
                nc._result(_call(sup, 'Runtime.callFunctionOn', {'objectId':roots,'functionDeclaration':'function(r){this.push(r)}','arguments':[{'objectId':obj}]}, sid))
            # Every visited document is a refusal canary, including empty siblings.
            dg = lease.keep(sid, nc._invoke(sup,sid,roots,'function(){return ('+GUARD_JS+')(this.slice())}',(),False)['objectId'])
            guards.append((sid,dg,shadows))
            doc=lease.keep(sid,nc._invoke(sup,sid,dg,'function(){return this.document}',(),False)['objectId'])
            lease.census_documents[(sid,dg)]=doc
            if not https_document:
                # An unrelated opaque service frame is a retained, metadata-only
                # refusal canary, not a secret destination or traversal authority.
                # Its document/navigation, root census and exact owner stay bound.
                return
            if actual == origin and (frame is None or frame == fid or frame == 'top' and fid == root):
                inspect = lease.keep(sid,nc._invoke(sup,sid,roots,'function(){return ('+EXPORT_JS+')(this.slice(),"input")}',(),False)['objectId'])
                raw = nc._invoke(sup,sid,inspect,'function(){return JSON.stringify(this.rows)}').get('value')
                if not isinstance(raw,str) or len(raw)>100000:
                    raise ValueError('login inspection capacity')
                rows=json.loads(raw)
                for row in rows:
                    c=classify_login_control(LoginControl.from_dict(row))
                    if c is None or c.token!='current-password' or row.get('type')!='password':
                        continue
                    obj=lease.keep(sid,nc._invoke(sup,sid,inspect,'function(i){return this.nodes[i]}',(row['index'],),False)['objectId'])
                    if field_selector is not None and nc._invoke(sup,sid,obj,'function(s){return this.matches(s)}',(field_selector,)).get('value') is not True:
                        continue
                    # Delay binding until uniqueness is established. Retain both
                    # destination and exact owner objects, never selectors.
                    candidates.append((sid,dg,obj,chain))
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
                visit(sid,child,depth+1,chain+((sid,dg,obj),))
        visit(sid,root,0)
        if len(candidates)!=1:
            raise ValueError('ambiguous login target')
        sid,dg,obj,chain=candidates[0]
        response=_call(sup,'Runtime.callFunctionOn',{'objectId':dg,
            'functionDeclaration':'function(e,d){return this.bind(e,d)}',
            'arguments':[{'objectId':obj},{'value':field_selector is None or bool(re.fullmatch(r'#[A-Za-z_][A-Za-z0-9_-]*', field_selector))}], 'returnByValue':True},sid)
        if nc._result(response).get('value') is not True:
            raise ValueError('login binding refused')
        for owner_sid,owner_guard,owner_obj in chain:
            response=_call(sup,'Runtime.callFunctionOn',{'objectId':owner_guard,
                'functionDeclaration':'function(e){return this.requireVisible(e)}',
                'arguments':[{'objectId':owner_obj}], 'returnByValue':True},owner_sid)
            if nc._result(response).get('value') is not True:
                raise ValueError('login frame hidden')
        target=LoginTarget(origin,ps.sid,sup,lease,tuple(guards),tuple(ancestry),(sid,dg),deadline)
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
    # Preserve dependent phases: every retained guard verdict precedes every
    # fresh document/root census. Never let an earlier census mask a late root.
    for sid,obj,_ in target.guards:
        if nc._invoke(target.supervisor,sid,obj,'function(){return this.valid()}').get('value') is not True:
            raise ValueError('login document changed')
    checked=set()
    for sid,obj,shadows in target.guards:
        doc=target.lease.census_documents[(sid,obj)]
        if (sid,doc) not in checked:
            checked.add((sid,doc))
            if nc._document_capacity(target.supervisor,sid,doc=doc,release=False)[0]!=shadows:
                raise ValueError('login roots changed')


def fill_login(target, handle, guard):
    from .nested_code import _invoke
    from .redaction_compat import register_context_secret
    started=False
    password=None
    try:
        with dispatch_scope(target.expires):
            guard()
            backend,meta=login_backend(handle,target.origin)
            assert_target(target)
            # Resolve only after exact destination and frozen human/session admission.
            guard()
            target.supervisor.check()
            if login_backend(handle,target.origin)[1]!=meta:
                raise ValueError('login metadata changed')
            password=backend.resolve_password(handle)
            if not isinstance(password,str) or not password:
                raise ValueError('password unavailable')
            register_context_secret(password,kind='secret')
            guard()
            assert_target(target)
            if login_backend(handle,target.origin)[1]!=meta:
                raise ValueError('login metadata changed')
            sid,obj=target.destination
            if _invoke(target.supervisor,sid,obj,'function(){return this.focus()}').get('value') is not True:
                raise ValueError('login focus refused')
            guard()
            assert_target(target)
            started=True
            result=_invoke(target.supervisor,sid,obj,'function(v){return this.write(v)}',(password,)).get('value')
            if result!={'written':True,'valid':True}:
                raise ValueError('login write unconfirmed')
            guard()
            assert_target(target)
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
            backend,meta=login_backend(handle,target.origin)
            ct.assert_target(target)
            guard()
            target.supervisor.check()
            if login_backend(handle,target.origin)[1]!=meta:
                raise ValueError('login metadata changed')
            code=backend.resolve_otp(handle)
            if not isinstance(code,str) or not code:
                return {'success':False,'status':'otp_unavailable'}
            register_context_secret(code,kind='otp')
            guard()
            ct.assert_target(target)
            if login_backend(handle,target.origin)[1]!=meta:
                raise ValueError('login metadata changed')
            if not ct.fill(target,code,target.expires):
                raise ValueError('otp unconfirmed')
            return {'success':True,'status':'filled','kind':'totp','origin':target.origin}
    except Exception:
        return {'success':False,'status':'unknown' if diagnostic['writes_attempted'] else 'target_refused'}
    finally:
        code=None
