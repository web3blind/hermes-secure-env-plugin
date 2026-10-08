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
from .bound_cdp import BoundCDP


# Retained references, including composed shadow ancestry, are authority.
# Unrelated UI changes are not authority changes.
_GUARD = r'''function(nodes, inspection=false, roots=[document], selector=null) {
  const doc=document, href=location.href, origin=self.origin;
  const path=e=>{const p=[];for(;e;e=e.parentNode||(e instanceof ShadowRoot?e.host:null))p.push(e);return p};
  const attrs=e=>JSON.stringify(Array.from(e.attributes||[],a=>[a.name,a.value]));
  const saved=nodes.map(e=>({e,path:path(e),attrs:attrs(e),form:e.form,
    formAttrs:e.form?attrs(e.form):null,action:e.form?.action,method:e.form?.method}));
  const protectedNodes=new Set(saved.flatMap(s=>[...s.path,s.form].filter(Boolean)));
  const labels=new Set(nodes.flatMap(e=>[...Array.from(e.labels||[]),
    ...(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>e.getRootNode().getElementById(id)).filter(Boolean)]));
  for(const l of labels){protectedNodes.add(l);for(const n of path(l))protectedNodes.add(n)}
  // MutationObserver does not cross shadow boundaries. Observe every composed
  // ancestry root, not only the iframe's immediate root and document.
  for(const n of protectedNodes){const root=n.getRootNode();if(!roots.includes(root))roots.push(root)}
  const selected=selector===null?[]:roots.flatMap(r=>Array.from(r.querySelectorAll(selector)));
  const snapshots=Array.from(protectedNodes,n=>[n,attrs(n)]);
  const touches=n=>Array.from(protectedNodes).some(p=>n===p||(n.contains&&n.contains(p)));
  const base=n=>n.nodeType===1&&(n.matches('base[href]')||n.querySelector('base[href]'));
  // Discovery uses the native classifier. Conservative semantic potential is
  // a refusal-only superset, including transient/reverted changes; never admission.
  const codeText=v=>/код/i.test(v||'')||/\b(?:code|pin|token|otp|totp|2fa|mfa|passcode)\b/i.test(String(v||'').normalize('NFKD').replace(/[^a-z0-9]+/gi,' '));
  const semantic=n=>n.nodeType===1&&(n.matches('iframe,frame')||
    (n.matches('input,select,label')&&(Array.from(n.attributes,a=>a.value).some(codeText)||
      (n.matches('label')&&codeText(n.textContent))||Array.from(n.labels||[],l=>l.textContent).some(codeText)||
      (n.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).some(id=>codeText(n.getRootNode().getElementById(id)?.textContent)))));
  const labelTouches=n=>n.nodeType===1&&(
    (n.matches('label')&&nodes.some(e=>e.id&&n.htmlFor===e.id))||
    nodes.some(e=>(e.getAttribute('aria-labelledby')||'').split(/\s+/).includes(n.id)&&n.id));
  // Token dependency witnesses are conservative for compound selectors: two
  // attributes can jointly match and revert within one observer batch. Never
  // reconstruct history from a clone with today's other attributes.
  // Relational/pseudo/escaped selectors keep conservative full dependencies.
  const simple=selector!==null&&/^(?:[a-zA-Z][\w-]*)?(?:[.#][\w-]+)*$/.test(selector);
  const selectorTouches=n=>selector!==null&&n.nodeType===1&&
    (n.matches(selector)||n.querySelector(selector));
  const selectorAttribute=r=>{
    if(selector===null)return false;
    if(!simple)return true;
    const prefix=r.attributeName==='id'?'#':r.attributeName==='class'?'.':null;
    if(prefix===null)return false;
    const values=[r.oldValue,r.target.getAttribute(r.attributeName)].flatMap(v=>r.attributeName==='class'?String(v||'').split(/\s+/):[v]);
    return Array.from(selector.matchAll(/([.#])([\w-]+)/g)).some(m=>m[1]===prefix&&values.includes(m[2]));
  };
  const authority=n=>n.nodeType===1&&(base(n)||semantic(n)||labelTouches(n)||selectorTouches(n)||
    Array.from(n.querySelectorAll('input,select,iframe,frame,label,[id]')).some(e=>semantic(e)||labelTouches(e)));
  const sources=new Set(), sourceIds=new Map();
  const collectSources=()=>{
    for(const root of roots){
      if(!sourceIds.has(root))sourceIds.set(root,new Set());
      for(const e of root.querySelectorAll('input[aria-labelledby],select[aria-labelledby]')){
        for(const id of e.getAttribute('aria-labelledby').split(/\s+/).filter(Boolean)){
          sourceIds.get(root).add(id);
          const source=root.getElementById(id);if(source)sources.add(source);
        }
      }
    }
  };
  const sourceRelated=n=>{collectSources();return Array.from(sources).some(s=>s===n||s.contains(n))};
  const sourceAttribute=r=>{
    if(r.attributeName!=='id'&&r.attributeName!=='aria-labelledby')return false;
    collectSources();
    const root=r.target.getRootNode(), ids=sourceIds.get(root)||new Set();
    if(r.attributeName==='id'){
      if(![r.oldValue,r.target.id].some(id=>id&&ids.has(id)))return false;
      sources.add(r.target);return codeText(r.target.textContent);
    }
    if(!r.target.matches('input,select'))return false;
    for(const id of [r.oldValue,r.target.getAttribute('aria-labelledby')].flatMap(v=>String(v||'').split(/\s+/).filter(Boolean))){
      ids.add(id);const source=root.getElementById(id);if(source){sources.add(source);if(codeText(source.textContent))return true;}
    }
    sourceIds.set(root,ids);return false;
  };
  sourceRelated(doc);
  const inLabel=n=>Array.from(labels).some(l=>l===n||l.contains(n));
  const relevant=r=>r.type==='attributes'?(protectedNodes.has(r.target)||inLabel(r.target)||sourceAttribute(r)||
    (r.target.matches('base')&&r.attributeName==='href')||semantic(r.target)||
    (r.target.matches('input,select,label')&&codeText(r.oldValue))||labelTouches(r.target)||
    (r.attributeName==='for'&&nodes.some(e=>e.id&&e.id===r.oldValue))||
    (r.attributeName==='id'&&nodes.some(e=>(e.getAttribute('aria-labelledby')||'').split(/\s+/).includes(r.oldValue)))||selectorAttribute(r)):
    r.type==='characterData'?((selector!==null&&!simple)||inLabel(r.target)||((sourceRelated(r.target)||r.target.parentElement?.closest('label'))&&(codeText(r.oldValue)||codeText(r.target.data)))):
    (selector!==null&&!simple)||[...r.addedNodes,...r.removedNodes].some(n=>touches(n)||authority(n)||
      ((sourceRelated(r.target)||(r.target.nodeType===1&&r.target.closest('label')))&&codeText(n.textContent)))||inLabel(r.target);
  let bad=false, closed=false;
  const historyLength=history.length;
  if(!self.navigation)throw Error('unsupported navigation authority');
  const dirty=()=>{bad=true};
  navigation.addEventListener('navigate',dirty);
  addEventListener('popstate',dirty);addEventListener('hashchange',dirty);
  const filled=new Map();
  const mutationsBad=records=>{
    collectSources();
    // Learn the whole batch's historical links before evaluating earlier records.
    for(const r of records)if(r.type==='attributes'&&r.attributeName==='aria-labelledby'&&r.target.matches('input,select')){
      const root=r.target.getRootNode();if(!sourceIds.has(root))sourceIds.set(root,new Set());
      for(const id of [r.oldValue,r.target.getAttribute('aria-labelledby')].flatMap(v=>String(v||'').split(/\s+/).filter(Boolean)))sourceIds.get(root).add(id);
    }
    for(const [root,ids] of sourceIds)for(const id of ids){const source=root.getElementById(id);if(source)sources.add(source);}
    for(const r of records)if(r.type==='attributes'&&r.attributeName==='id'){
      const ids=sourceIds.get(r.target.getRootNode());
      if(ids&&[r.oldValue,r.target.id].some(id=>id&&ids.has(id)))sources.add(r.target);
    }
    return records.some(relevant);
  };
  const observer=new MutationObserver(r=>{if(mutationsBad(r))bad=true});
  const observe=root=>observer.observe(root,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true,characterDataOldValue:true});
  for(const root of roots)observe(root);
  const focused=e=>{let active=doc.activeElement;for(const root of roots)if(root instanceof ShadowRoot&&root.host===active&&root.activeElement)active=root.activeElement;return active===e};
  const valid=()=>{
    if(mutationsBad(observer.takeRecords()))bad=true;
    if(snapshots.some(([n,a])=>attrs(n)!==a))bad=true;
    if(selector!==null&&!inspection){const matches=roots.filter(r=>r===doc||r.host.isConnected).flatMap(r=>Array.from(r.querySelectorAll(selector)));
      if(matches.length!==selected.length||matches.some((e,i)=>e!==selected[i]))bad=true;}
    if(Array.from(filled).some(([i,v])=>saved[i].e.value!==v))bad=true;
    return !bad&&!closed&&document===doc&&self.origin===origin&&location.href===href&&history.length===historyLength&&
      saved.every(s=>s.e.isConnected&&s.e.ownerDocument===doc&&attrs(s.e)===s.attrs&&
        path(s.e).length===s.path.length&&path(s.e).every((n,i)=>n===s.path[i])&&
        s.e.form===s.form&&(!s.form||(s.form.isConnected&&attrs(s.form)===s.formAttrs&&s.form.action===s.action&&s.form.method===s.method))&&
        (inspection||(!s.e.matches(':disabled')&&!s.e.readOnly&&!path(s.e).some(n=>n.nodeType===1&&n.hasAttribute('inert'))&&s.e.getClientRects().length&&
        getComputedStyle(s.e).display!=='none'&&getComputedStyle(s.e).visibility==='visible')));
  };
  return Object.freeze({document:doc,valid,
    censusRoot(root){if(!roots.includes(root)){roots.push(root);observe(root);
      if(Array.from(root.querySelectorAll('input,select,iframe,frame,label')).some(semantic))bad=true;}return valid()},
    censusNode(n){if(authority(n))bad=true;return valid()},
    close(){closed=true;observer.disconnect();navigation.removeEventListener('navigate',dirty);
    removeEventListener('popstate',dirty);removeEventListener('hashchange',dirty);filled.clear();selected.length=0;saved.length=0;nodes.length=0;roots.length=0;protectedNodes.clear();labels.clear();sources.clear();sourceIds.clear();snapshots.length=0},
    focus(i){if(!valid())return false;saved[i].e.focus();return valid()&&doc.hasFocus()&&focused(saved[i].e)},
    write(i,value){if(!valid()||!doc.hasFocus()||!focused(saved[i].e))return {written:false,valid:false};
      const e=saved[i].e;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
      filled.set(i,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));
      return {written:true,valid:valid()&&doc.hasFocus()&&focused(e)};}
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
        self.censuses = {}
        self.contexts = {}
        self.scopes = []
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
        root = _call(sup, 'DOM.describeNode', {'objectId': doc, 'depth': 128, 'pierce': True}, sid)['result']['node']
        pending, count, shadows, controls = [root], 0, [], []
        while pending:
            node = pending.pop()
            count += 1
            if count > 10000:
                raise ValueError('unsupported document capacity')
            if node.get('nodeName', '').upper() in {'INPUT', 'SELECT', 'IFRAME', 'FRAME'}:
                controls.append(node['backendNodeId'])
                if len(controls) > 200:
                    raise ValueError('control capacity')
            custom = [s for s in node.get('shadowRoots', []) if s.get('shadowRootType') != 'user-agent']
            shadows.extend(s['backendNodeId'] for s in custom)
            if len(shadows) > 128:
                raise ValueError('unsupported document capacity')
            pending.extend(custom)
            children = node.get('children', [])
            if node.get('childNodeCount', 0) > len(children):
                raise ValueError('unsupported document depth')
            pending.extend(children)
        return tuple(shadows), tuple(sorted(controls))
    finally:
        _call(sup, 'Runtime.releaseObject', {'objectId': doc}, sid)


def _inspection_js(nonce, selector):
    from agent.vault_login_classifier import build_inspection_js
    # Keep native metadata/semantics; replace only its light-DOM collection and
    # scope accessible names to each control's own root. No secret values read.
    native = build_inspection_js(nonce).replace(
        'document.querySelectorAll("input, select")', 'query("input, select")').replace(
        'Array.from(document.forms)', 'query("form")').replace(
        'document.getElementById(id)', 'element.getRootNode().getElementById(id)')
    return 'function(){const roots=this.slice();const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));const rows=JSON.parse(' + native + ');const selector=' + json.dumps(selector) + r''';
      const nodes=query("input,select");
      const matches=selector===null?[]:query(selector);
      for(const row of rows){
        const e=nodes[row.index];
        row.selected=matches.includes(e)&&!e.matches(':disabled')&&!e.closest('[inert]')&&
          e.getAttribute('aria-disabled')!=='true'&&e.getAttribute('aria-readonly')!=='true'&&
          getComputedStyle(e).visibility==='visible';
        row.inputMode=e.inputMode;row.fieldName=e.name;row.rootIndex=roots.indexOf(e.getRootNode());
      }
      const raw=JSON.stringify(rows);const guard=(''' + _GUARD + r''')(nodes.slice(),true,roots.slice(),selector);
      return {raw,nodes,roots,selector,matchCount:matches.length,href:location.href,guard,close(){guard.close()}};
    }'''


def discover(origin, label, task, parent, field_selector=None, *, top_only=False):
    from .code_targets import validate_field_selector
    validate_field_selector(field_selector, parent)
    sup = _supervisor(task)
    from .parent_session import ParentSession, TopSession
    parent_session = TopSession(sup, parent) if top_only else ParentSession(sup, parent)
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
        actual = _eval(sup, sid, context, 'self.origin', True).get('value')
        strict_origin(actual)  # Opaque/sandbox/non-HTTPS ancestors are unsupported.
        shadows, census = _document_capacity(sup, sid, context)
        roots = lease.keep(sid, _eval(sup, sid, context, '[document]')['objectId'])
        for backend in shadows:
            obj = lease.keep(sid, _call(sup, 'DOM.resolveNode', {'backendNodeId': backend, 'executionContextId': context}, sid)['result']['object']['objectId'])
            _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': roots, 'functionDeclaration': 'function(root){this.push(root)}', 'arguments': [{'objectId': obj}], 'returnByValue': True}, sid))
        if actual == origin:
            nonce = secrets.token_hex(12)
            inspector = lease.keep(sid, _invoke(sup, sid, roots,
                _inspection_js(nonce, field_selector), (), False)['objectId'])
            raw = _invoke(sup, sid, inspector, 'function(){return this.raw}').get('value')
            if not isinstance(raw, str) or len(raw) > 100000:
                raise ValueError('inspection capacity')
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > 200:
                raise ValueError('control capacity')
            if field_selector is not None:
                selector_matches.append(_invoke(sup, sid, inspector, 'function(){return this.matchCount}').get('value'))
                scope = lease.keep(sid, _invoke(sup, sid, inspector,
                    'function(){if(!this.guard.valid())throw Error();return (' + _GUARD + ')([],false,this.roots.slice(),this.selector)}', (), False)['objectId'])
                lease.censuses[scope] = (shadows, census)
                lease.contexts[scope] = context
                lease.scopes.append((sid, scope, ancestry))
            groups = {}
            root_indices = {r['index']: r['rootIndex'] for r in rows}
            classified = _classified(rows, explicit=True) if field_selector is not None else _classified(rows)
            for c in classified:
                groups.setdefault((root_indices[c.control.index], c.control.form_index), []).append(c)
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
                    'function(indices){if(!this.guard.valid())throw Error();return (' + _GUARD + ')(indices.map(i=>this.nodes[i]),false,this.roots.slice(),this.selector)}',
                    ([c.control.index for c in controls],), False)['objectId'])
                lease.censuses[guard] = (shadows, census)
                lease.contexts[guard] = context
                href = _invoke(sup, sid, inspector, 'function(){return this.href}').get('value')
                targets.append(NestedCodeTarget(origin, label, task, parent, nonce, href,
                    tuple(controls), sup, parent, frame, psid, sid, guard, ancestry, lease,
                    time.monotonic() + 240, field_selector=field_selector, explicit_parent=not top_only))
        if top_only:
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
                'function(){if(this.hasAttribute("sandbox")&&!this.sandbox.contains("allow-same-origin"))throw Error();return (' + _GUARD + ')([this],false,[document,this.getRootNode()].filter((r,i,a)=>a.indexOf(r)===i))}', (), False)['objectId'])
            lease.censuses[guard] = (shadows, census)
            lease.contexts[guard] = context
            visit(sid, child, ancestry + ((sid, frame, child, owner, guard),), depth + 1)

    try:
        root = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
        visit(psid, root, (), 0)
        if field_selector is not None:
            if sum(selector_matches) > 1:
                raise ValueError('ambiguous code selector')
            if sum(selector_matches) != 1 or len(targets) != 1:
                raise ValueError('inadmissible code selector')
        lease.refs = len(targets)
        scope_objects = {(sid, guard) for sid, guard, _ in lease.scopes}
        scope_objects |= {(a[0], a[4]) for _, _, ancestors in lease.scopes for a in ancestors}
        scope_sessions = {sid for sid, _ in scope_objects}
        for target in targets:
            assert_target(target)
            lease.resources[target.leaf_guard] = (
                {(target.leaf_sid, target.leaf_guard)} | {(a[0], a[4]) for a in target.ancestry} | scope_objects,
                {target.parent_sid, target.leaf_sid} | {a[0] for a in target.ancestry} | scope_sessions)
        lease.prune()  # Inspection/temporary node arrays are no longer authorities.
        if not targets:
            lease.close()
        return targets
    except BaseException:
        lease.close()
        raise


def _check_census(target, sid, guard):
    """Complete bounded census; differential checks never replace retained targets."""
    sup, lease = target.supervisor, target.lease
    doc = _invoke(sup, sid, guard, 'function(){return this.document}', (), False)['objectId']
    current = _document_capacity(sup, sid, doc=doc)
    previous = lease.censuses[guard]
    added = [(backend, 'censusRoot') for backend in current[0] if backend not in previous[0]]
    added += [(backend, 'censusNode') for backend in current[1] if backend not in previous[1]]
    for backend, check in added:
        obj = _call(sup, 'DOM.resolveNode', {'backendNodeId': backend,
            'executionContextId': lease.contexts[guard]}, sid)['result']['object']['objectId']
        try:
            result = _result(_call(sup, 'Runtime.callFunctionOn', {'objectId': guard,
                'functionDeclaration': 'function(n){return this.' + check + '(n)}',
                'arguments': [{'objectId': obj}], 'returnByValue': True}, sid))
            if result.get('value') is not True:
                raise ValueError('code document changed')
        finally:
            _call(sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
    lease.censuses[guard] = current


def assert_target(target):
    sup = _supervisor(target.task)
    if (sup is not getattr(target.supervisor, 'raw', target.supervisor) or target.lease.closed or time.monotonic() >= target.expires
            or (target.lease.parent_session.check() if target.lease.parent_session is not None
                else _parent(sup, target.parent)) != target.parent_sid):
        raise ValueError('stale nested target')
    sup = target.supervisor
    checked = set()
    ancestors = list(target.ancestry)
    ancestors += [a for _, _, path in target.lease.scopes for a in path]
    for sid, frame, child, owner, guard in ancestors:
        if (sid, guard) in checked:
            continue
        checked.add((sid, guard))
        if _call(sup, 'DOM.getFrameOwner', {'frameId': child}, sid)['result']['backendNodeId'] != owner:
            raise ValueError('frame owner changed')
        if _invoke(sup, sid, guard, 'function(){return this.valid()}').get('value') is not True:
            raise ValueError('ancestor changed')
        _check_census(target, sid, guard)
    for sid, guard, _ in target.lease.scopes:
        if _invoke(sup, sid, guard, 'function(){return this.valid()}').get('value') is not True:
            raise ValueError('code document changed')
        _check_census(target, sid, guard)
    if _invoke(sup, target.leaf_sid, target.leaf_guard, 'function(){return this.valid()}').get('value') is not True:
        raise ValueError('code document changed')
    _check_census(target, target.leaf_sid, target.leaf_guard)


def fill(target, code, expires_at):
    from agent.vault_login_classifier import build_otp_fills
    from .redaction_compat import register_context_secret
    register_context_secret(code, kind='otp')
    fills = build_otp_fills(list(target.controls), code)
    if not fills or len(fills) != len(target.controls):
        raise ValueError('invalid code fields')
    maximum = target.controls[0].control.max_length
    if len(fills) == 1 and maximum is not None and maximum < len(code):
        raise ValueError('code too long')
    if not target.explicit_parent:
        # Historical top-level fill emulation is not a discovery side effect.
        _call(target.supervisor, 'Emulation.setFocusEmulationEnabled', {'enabled': True}, target.leaf_sid)
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
