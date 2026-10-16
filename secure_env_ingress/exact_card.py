"""Explicit, geometry-independent native-card targets. No secret tool arguments.

Only bounded simple selectors are supported: their complete attribute dependency
is provable. References, not selectors or visual layout, remain write authority.
"""
from dataclasses import dataclass, field
import json
import re
import time
import unicodedata

from .vault_ingress import strict_origin
from .bound_cdp import BoundCDP
from .exact_code import PLAIN_EDITOR_JS


class _CardCDP(BoundCDP):
    """Frozen-profile human lease re-admission at the actual native send fence."""
    def __init__(self, sup, home, task):
        super().__init__(sup)
        from tools.browser_vault_tool import _bot_desktop_browser_session
        self.lease_check = lambda: None
        if _bot_desktop_browser_session(task):
            from tools.bot_desktop import lease
            key = str(home)
            epoch = lease.assert_agent_may_act(key).epoch
            def check():
                if lease.assert_agent_may_act(key).epoch != epoch:
                    raise ValueError('card human lease changed')
            self.lease_check = check

    def check(self):
        super().check()
        self.lease_check()

FORMATS = {'pan': ('digits', 'space4', 'hyphen4'), 'cardholder': ('text',),
           'expiry': ('MM/YY', 'MM/YYYY', 'MMYY', 'MMYYYY', 'MM-YY', 'MM-YYYY'),
           'month': ('MM', 'M'), 'year': ('YY', 'YYYY'), 'cvc': ('digits',)}


def validate_spec(spec, parent):
    if (not isinstance(parent, str) or not parent or not isinstance(spec, dict) or
            set(spec) != {'version', 'purpose', 'merchant_origin', 'fields'} or
            type(spec['version']) is not int or spec['version'] != 1 or spec['purpose'] != 'payment_card'):
        raise ValueError('invalid card target')
    strict_origin(spec['merchant_origin'])
    fields = spec['fields']
    if not isinstance(fields, list) or not 3 <= len(fields) <= 23:
        raise ValueError('invalid card target')
    for f in fields:
        if not isinstance(f, dict) or set(f) not in ({'role', 'selector', 'frame', 'format'}, {'role', 'selector', 'frame', 'format', 'part', 'length'}):
            raise ValueError('invalid card target')
        if (f['role'] not in FORMATS or f['format'] not in FORMATS[f['role']] or
                not isinstance(f['frame'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', f['frame']) or
                not isinstance(f['selector'], str) or not 1 <= len(f['selector']) <= 256 or
                not re.fullmatch(r'(?:[a-zA-Z][\w-]*)?(?:[.#][\w-]+)+', f['selector'], flags=re.ASCII)):
            raise ValueError('invalid card target')
        if 'part' in f and (f['role'] != 'pan' or f['format'] != 'digits' or
                            type(f['part']) is not int or type(f['length']) is not int or not 1 <= f['length'] <= 19):
            raise ValueError('invalid card target')
    roles = [f['role'] for f in fields]
    if (roles.count('cvc') != 1 or roles.count('cardholder') > 1 or roles.count('expiry') > 1 or
            roles.count('month') > 1 or roles.count('year') > 1 or
            not (roles.count('expiry') == 1 and 'month' not in roles and 'year' not in roles or
                 'expiry' not in roles and roles.count('month') == roles.count('year') == 1)):
        raise ValueError('invalid card target')
    pan = [f for f in fields if f['role'] == 'pan']
    if not pan or (len(pan) == 1 and 'part' not in pan[0]):
        if len(pan) != 1:
            raise ValueError('invalid card target')
    elif (any('part' not in f for f in pan) or [f['part'] for f in pan] != list(range(len(pan))) or
          not 12 <= sum(f['length'] for f in pan) <= 19):
        raise ValueError('invalid card target')
    if len({(f['frame'], f['selector']) for f in fields}) != len(fields):
        raise ValueError('invalid card target')
    return json.loads(json.dumps(spec, sort_keys=True))


def schema():
    return {'type': 'object', 'additionalProperties': False,
            'required': ['version', 'purpose', 'merchant_origin', 'fields'], 'properties': {
                'version': {'type': 'integer', 'enum': [1]}, 'purpose': {'type': 'string', 'enum': ['payment_card']},
                'merchant_origin': {'type': 'string'}, 'fields': {'type': 'array', 'minItems': 3, 'maxItems': 23,
                'items': {'type': 'object', 'additionalProperties': False, 'required': ['role', 'selector', 'frame', 'format'],
                          'properties': {'role': {'type': 'string', 'enum': list(FORMATS)},
                                         'selector': {'type': 'string', 'maxLength': 256}, 'frame': {'type': 'string'},
                                         'format': {'type': 'string', 'enum': sorted({v for values in FORMATS.values() for v in values})},
                                         'part': {'type': 'integer', 'minimum': 0, 'maximum': 18},
                                         'length': {'type': 'integer', 'minimum': 1, 'maximum': 19}}}}}}


def values_for(spec, secret):
    # Reuse authoritative native storage validation including Luhn, expiry and LF.
    from .payment import payment_secret, PAYMENT_FIELDS
    values = [secret.get(k, '') for k in PAYMENT_FIELDS]
    valid = payment_secret(values)
    pan, month, year, cvc = (valid[k] for k in ('card_number', 'exp_month', 'exp_year', 'cvc'))
    parts = [f for f in spec['fields'] if f['role'] == 'pan' and 'part' in f]
    if parts and sum(f['length'] for f in parts) != len(pan):
        raise ValueError('card format mismatch')
    result, offset = [], 0
    for f in spec['fields']:
        role, fmt = f['role'], f['format']
        if role == 'pan':
            if 'part' in f:
                value = pan[offset:offset + f['length']]
                offset += f['length']
            else:
                sep = {'digits': '', 'space4': ' ', 'hyphen4': '-'}[fmt]
                value = sep.join(pan[i:i + 4] for i in range(0, len(pan), 4)) if sep else pan
        elif role == 'cardholder':
            value = valid.get('cardholder_name', '')
            if not value:
                raise ValueError('missing cardholder')
        elif role == 'cvc':
            value = cvc
        elif role == 'month':
            value = month if fmt == 'MM' else str(int(month))
        elif role == 'year':
            value = year if fmt == 'YYYY' else year[-2:]
        else:
            value = fmt.replace('YYYY', year).replace('YY', year[-2:]).replace('MM', month)
        if not value or any(unicodedata.category(c).startswith('C') or unicodedata.category(c) in ('Zl', 'Zp') or c in '\r\n' for c in value):
            raise ValueError('invalid card format')
        result.append(value)
    return result


GUARD_JS = r'''function(roots, fields, owners=[]){
 const doc=document,href=location.href,origin=self.origin;
 const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
 const path=e=>{let p=[];for(;e;e=e.parentNode||(e instanceof ShadowRoot?e.host:null))p.push(e);return p};
 // Inline paint/layout is not setter authority for a retained explicit node.
 // Simple selectors cannot depend on style; focus is checked on the real node.
 const attrs=e=>JSON.stringify(Array.from(e.attributes||[]).filter(a=>a.name!=='style').map(a=>[a.name,a.value]));
 const read=e=>e.matches('input,textarea')?e.value:e.textContent;
 const form=e=>e.matches('input,textarea')?e.form:e.closest('form');
 const focused=e=>{let active=doc.activeElement;for(const r of roots)if(r instanceof ShadowRoot&&r.host===active&&r.activeElement)active=r.activeElement;return active===e};
 const nodes=owners.length?owners:fields.map(f=>{const m=query(f.selector);if(m.length!==1)throw Error();return m[0]});
 if(new Set(nodes).size!==nodes.length)throw Error();
 const expected={pan:'cc-number',cardholder:'cc-name',expiry:'cc-exp',month:'cc-exp-month',year:'cc-exp-year',cvc:'cc-csc'};
 const labels=new Set();
 for(let i=0;i<fields.length;i++){
  const e=nodes[i],f=fields[i];
  if(!e.matches('input,textarea,[contenteditable="plaintext-only"],[contenteditable="true"]')||
    (e.matches('input')&&!['text','tel'].includes(e.type))||
    (!e.matches('input,textarea')&&!(__PLAIN_EDITOR__)(e,roots))||
    e.matches(':disabled')||e.readOnly||e.closest('[inert]')||e.getAttribute('aria-disabled')==='true'||e.getAttribute('aria-readonly')==='true')throw Error();
  const ac=(e.autocomplete||e.getAttribute('autocomplete')||'').trim().toLowerCase().split(/\s+/).filter(Boolean);
  if(ac.length&&!((ac.length===1&&['off','on'].includes(ac[0]))||
    (ac.at(-1)===expected[f.role]&&ac.slice(0,-1).every(t=>['billing','shipping'].includes(t)||/^section-[a-z0-9_-]+$/.test(t))&&
      ac.filter(t=>t==='billing'||t==='shipping').length<=1&&ac.filter(t=>t.startsWith('section-')).length<=1)))throw Error();
  const ls=[...Array.from(e.labels||[]),...(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>e.getRootNode().getElementById(id)).filter(Boolean)];
  ls.forEach(l=>labels.add(l));
  const text=[e.getAttribute('name'),e.id,e.getAttribute('aria-label'),e.getAttribute('placeholder'),e.getAttribute('title'),...ls.map(l=>l.textContent)]
    .join(' ').replace(/([a-z])([A-Z])/g,'$1 $2').normalize('NFKC').toLowerCase();
  if(/captcha|password|passwd|passphrase|user[ _-]*name|e-?mail|\b(pwd|otp|totp|passcode|recovery|backup|seed|promo|credential|secret|jwt)\b|one[ _-]*time[ _-]*(?:code|password)|(?:verification|confirmation)[ _-]*code|(?:api|private|signing)[ _-]*(?:key|token)|(?:access|bearer|refresh|auth)[ _-]*token|парол|код[ _-]*(?:подтверждения|верификации)|одноразов/.test(text))throw Error();
  if(form(e)&&new URL(form(e).action,doc.baseURI).origin!==origin)throw Error();
 }
 if(nodes.length&&nodes.some(e=>e.getRootNode()!==nodes[0].getRootNode()||form(e)!==form(nodes[0])))throw Error();
 const snapshots=nodes.map(e=>({e,path:path(e),attrs:attrs(e),form:form(e),action:form(e)?.action,method:form(e)?.method}));
 const protectedNodes=new Set([...snapshots.flatMap(s=>[...s.path,...(s.form?path(s.form):[])]),...Array.from(labels).flatMap(path)]);
 for(const l of labels)for(const n of l.querySelectorAll('*'))protectedNodes.add(n);
 for(const n of protectedNodes){const r=n.getRootNode();if(!roots.includes(r))roots.push(r)}
 const saved=Array.from(protectedNodes,n=>[n,attrs(n)]),filled=new Map();
 let stale=false,own=null,closed=false;
 const historyLength=history.length;
 // Same-document navigation is sticky even if the original URL is restored.
 // Without Navigation API, replaceState-away-and-back has no reliable native
 // event; fail closed rather than patching a website's History API methods.
 if(!self.navigation)throw Error('unsupported navigation authority');
 const dirty=()=>{stale=true};
 navigation.addEventListener('navigate',dirty);
 addEventListener('popstate',dirty);addEventListener('hashchange',dirty);
 const tokens=fields.flatMap(f=>Array.from(f.selector.matchAll(/([.#])([\w-]+)/g),m=>[m[1],m[2]]));
 const selectorAttr=r=>tokens.some(([p,t])=>r.attributeName===(p==='#'?'id':'class')&&[r.oldValue,r.target.getAttribute(r.attributeName)].some(v=>p==='#'?v===t:String(v||'').split(/\s+/).includes(t)));
 const hasMatch=n=>n.nodeType===1&&fields.some(f=>n.matches(f.selector)||n.querySelector(f.selector));
 const historicRoots=new WeakMap();
 const learn=(n,r)=>{for(const e of [n,...Array.from(n.querySelectorAll?.('*')||[])]){if(!historicRoots.has(e))historicRoots.set(e,new Set());historicRoots.get(e).add(r)}};
 roots.forEach(r=>learn(r,r));
 const sameRoot=(n,e)=>n.getRootNode()===e.getRootNode()||historicRoots.get(n)?.has(e.getRootNode());
 const relatedLabel=n=>n.nodeType===1&&n.matches('label')&&nodes.some(e=>e.id&&n.htmlFor===e.id&&sameRoot(n,e));
 const labelTouch=n=>Array.from(labels).some(l=>l===n||l.contains(n))||relatedLabel(n);
 const addedLabel=n=>relatedLabel(n)||(n.nodeType===1&&Array.from(n.querySelectorAll('label')).some(relatedLabel));
 const base=n=>n.nodeType===1&&(n.matches('base')||n.querySelector('base'));
 const records=(rs,root)=>{
  // Learn removed-subtree roots before evaluating the complete mutation batch.
  for(const r of rs){learn(r.target,root);if(r.type==='childList')for(const n of [...r.addedNodes,...r.removedNodes])learn(n,root)}
  for(const r of rs){
   if(r.type==='attributes'&&r.attributeName==='style')continue;
   if(own&&r===own.record)continue;
   if(r.type==='attributes'&&(protectedNodes.has(r.target)||selectorAttr(r)||labelTouch(r.target)||
     (r.target.matches('label')&&r.attributeName==='for'&&nodes.some(e=>e.id===r.oldValue&&sameRoot(r.target,e)))||
     (r.target.matches('base')&&r.attributeName==='href')))stale=true;
   if(r.type==='characterData'&&(labelTouch(r.target)||nodes.some(n=>n.contains(r.target))))stale=true;
   if(r.type==='childList'&&(labelTouch(r.target)||nodes.includes(r.target)||
      [...r.addedNodes,...r.removedNodes].some(n=>base(n)||hasMatch(n)||addedLabel(n)||Array.from(protectedNodes).some(p=>n===p||n.contains?.(p)))))stale=true;
  }
 };
 const observers=roots.map(r=>{const o=new MutationObserver(rs=>records(rs,r));o.root=r;o.observe(r,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true,characterDataOldValue:true});return o});
 const valid=()=>{
  observers.forEach(o=>records(o.takeRecords(),o.root));
  if(stale||closed||doc!==document||href!==location.href||origin!==self.origin||history.length!==historyLength||!doc.defaultView)return false;
  if(saved.some(([n,a])=>attrs(n)!==a))return false;
  for(let i=0;i<nodes.length;i++){
   const s=snapshots[i],e=s.e,p=path(e),matches=fields[i]?query(fields[i].selector):[e];
   if(matches.length!==1||matches[0]!==e||!e.isConnected||p.length!==s.path.length||p.some((n,j)=>n!==s.path[j])||
    form(e)!==s.form||s.action!==form(e)?.action||s.method!==form(e)?.method||e.matches(':disabled')||e.readOnly||e.closest('[inert]')||
    (e.matches('[contenteditable]')&&(!e.isContentEditable||(e.parentElement||e.getRootNode().host)?.isContentEditable||
      e.children.length||Array.from(e.childNodes).some(n=>n.nodeType!==3))))return false;
   if(filled.has(e)&&read(e)!==filled.get(e))return false;
  }
  return true;
 };
 return {valid,document:doc,close(){closed=true;observers.forEach(o=>o.disconnect());navigation.removeEventListener('navigate',dirty);
  removeEventListener('popstate',dirty);removeEventListener('hashchange',dirty)},
  prepare(values){return valid()&&values.length===nodes.length&&nodes.every((e,i)=>!read(e)&&(!e.maxLength||e.maxLength<0||values[i].length<=e.maxLength)&&!/[\r\n]/.test(values[i]))},
  focus(i){if(!valid())return false;const e=nodes[i];e.focus();return doc.hasFocus()&&focused(e)&&valid()},
  write(i,v){if(!valid()||!doc.hasFocus()||!focused(nodes[i])||filled.has(nodes[i])||read(nodes[i])||/[\r\n]/.test(v))return {written:false,valid:false};const e=nodes[i];
   if(e.matches('input,textarea'))Object.getOwnPropertyDescriptor(e.matches('input')?HTMLInputElement.prototype:HTMLTextAreaElement.prototype,'value').set.call(e,v);
   else {
    const before=Array.from(e.childNodes);
    Object.getOwnPropertyDescriptor(Node.prototype,'textContent').set.call(e,v);
    const rs=observers.flatMap(o=>o.takeRecords());
    const r=rs.find(r=>r.type==='childList'&&r.target===e);
    if(!r||rs.filter(r=>r.type==='childList'&&r.target===e).length!==1||
      r.removedNodes.length!==before.length||Array.from(r.removedNodes).some((n,j)=>n!==before[j]||n.nodeType!==3)||
      r.addedNodes.length!==1||r.addedNodes[0]!==e.firstChild||e.childNodes.length!==1||
      r.addedNodes[0].nodeType!==3||r.addedNodes[0].textContent!==v)stale=true;
    own={record:r};records(rs,e.getRootNode());own=null;
    const range=doc.createRange();range.selectNodeContents(e);range.collapse(false);
    const selection=doc.getSelection();selection.removeAllRanges();selection.addRange(range);
   }
   observers.forEach(o=>records(o.takeRecords(),o.root));own=null;filled.set(e,v);
   e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));
   return {written:true,valid:read(e)===v&&doc.hasFocus()&&focused(e)&&valid()};}
 };
}'''.replace('__PLAIN_EDITOR__', PLAIN_EDITOR_JS)


@dataclass(frozen=True)
class CardTarget:
    task: str
    parent: str
    origin: str
    spec: dict = field(repr=False)
    supervisor: object = field(repr=False)
    lease: object = field(repr=False)
    parent_sid: str
    guards: tuple = field(repr=False)
    ancestry: tuple = field(repr=False)
    expires: float


def discover(task, parent, origin, spec):
    from . import nested_code as nc
    from .code_targets import _supervisor, _call
    from .parent_session import ParentSession
    spec = validate_spec(spec, parent)
    strict_origin(origin)
    parent_session = ParentSession(_supervisor(task), parent)
    try:
        parent_session.transport = _CardCDP(parent_session.sup, parent_session.home, task)
    except BaseException:
        parent_session.drop(None)
        raise
    sup, psid = parent_session.transport, parent_session.sid
    lease = nc._Lease(sup)
    lease.parent_session = parent_session
    visited, guards, ancestry, found = set(), [], [], set()
    deadline = time.monotonic() + 120
    try:
        root = _call(sup, 'Page.getFrameTree', {}, psid)['result']['frameTree']['frame']['id']
        def visit(sid, frame, depth, path=()):
            if depth > 8 or frame in visited or len(visited) >= 40 or time.monotonic() >= deadline:
                raise ValueError('card traversal capacity')
            visited.add(frame)
            sid, context = nc._context(sup, sid, frame, lease)
            actual = nc._eval(sup, sid, context, 'self.origin', True).get('value')
            fields = [(i, f) for i, f in enumerate(spec['fields']) if f['frame'] == frame or f['frame'] == 'top' and frame == root]
            try:
                strict_origin(actual)
            except ValueError:
                if fields or frame == root:
                    raise
                return  # Opaque unrelated branches confer no destination authority.
            if frame == root and actual != spec['merchant_origin']:
                raise ValueError('merchant mismatch')
            shadows, census = nc._document_capacity(sup, sid, context)
            roots = lease.keep(sid, nc._eval(sup, sid, context, '[document]')['objectId'])
            for backend in shadows:
                obj = lease.keep(sid, _call(sup, 'DOM.resolveNode', {'backendNodeId': backend, 'executionContextId': context}, sid)['result']['object']['objectId'])
                nc._result(_call(sup, 'Runtime.callFunctionOn', {'objectId': roots, 'functionDeclaration': 'function(r){this.push(r)}', 'arguments': [{'objectId': obj}]}, sid))
            if fields:
                if actual != origin:
                    raise ValueError('provider mismatch')
                guard = lease.keep(sid, nc._invoke(sup, sid, roots, 'function(fs){return (' + GUARD_JS + ')(this.slice(),fs)}', ([f for _, f in fields],), False)['objectId'])
                guards.append((sid, guard, tuple(i for i, _ in fields)))
                ancestry.extend(path)
                found.update(i for i, _ in fields)
            # Owner closures bind merchant navigation even for a top-level target.
            if fields or frame == root:
                docguard = lease.keep(sid, nc._invoke(sup, sid, roots, 'function(){return (' + GUARD_JS + ')(this.slice(),[])}', (), False)['objectId'])
                lease.censuses[docguard] = (shadows, census)
                guards.append((sid, docguard, ()))
            owners = lease.keep(sid, nc._invoke(sup, sid, roots, 'function(){return this.flatMap(r=>Array.from(r.querySelectorAll("iframe,frame")))}', (), False)['objectId'])
            count = nc._invoke(sup, sid, owners, 'function(){return this.length}').get('value')
            if type(count) is not int or count > 20:
                raise ValueError('card frame capacity')
            for i in range(count):
                obj = lease.keep(sid, nc._invoke(sup, sid, owners, 'function(i){return this[i]}', (i,), False)['objectId'])
                node = _call(sup, 'DOM.describeNode', {'objectId': obj}, sid)['result']['node']
                child, owner = node.get('frameId'), node['backendNodeId']
                if not child or _call(sup, 'DOM.getFrameOwner', {'frameId': child}, sid)['result']['backendNodeId'] != owner:
                    raise ValueError('card owner mismatch')
                guard = lease.keep(sid, nc._invoke(sup, sid, obj, 'function(){return (' + GUARD_JS + ')([document,this.getRootNode()].filter((r,i,a)=>a.indexOf(r)===i),[],[this])}', (), False)['objectId'])
                visit(sid, child, depth + 1, path + ((sid, child, owner, guard),))
        visit(psid, root, 0)
        if found != set(range(len(spec['fields']))):
            raise ValueError('missing card targets')
        target = CardTarget(task, parent, origin, spec, sup, lease, psid, tuple(guards), tuple(ancestry), deadline)
        assert_target(target)
        return [target]
    except BaseException:
        lease.close()
        raise


def assert_target(target):
    from .code_targets import _call
    from .nested_code import _invoke
    if (not target.supervisor.valid() or
            target.lease.closed or time.monotonic() >= target.expires or target.lease.parent_session.check() != target.parent_sid):
        raise ValueError('stale card target')
    for sid, child, owner, guard in target.ancestry:
        if _call(target.supervisor, 'DOM.getFrameOwner', {'frameId': child}, sid)['result']['backendNodeId'] != owner:
            raise ValueError('card owner changed')
        if _invoke(target.supervisor, sid, guard, 'function(){return this.valid()}').get('value') is not True:
            raise ValueError('card ancestry changed')
    for sid, guard, _ in target.guards:
        if _invoke(target.supervisor, sid, guard, 'function(){return this.valid()}').get('value') is not True:
            raise ValueError('card document changed')
        if guard in target.lease.censuses:
            from .nested_code import _document_capacity
            doc = _invoke(target.supervisor, sid, guard, 'function(){return this.document}', (), False)['objectId']
            current = _document_capacity(target.supervisor, sid, doc=doc)
            if current[0] != target.lease.censuses[guard][0]:
                raise ValueError('card roots changed')


def release(target):
    target.lease.close()


def approved_fill(target, handle, scope_guard):
    from .bound_cdp import dispatch_scope
    with dispatch_scope(target.expires):
        from .payment_fill import payment_backend
        from .nested_code import _invoke
        from tools.browser_vault_tool import _confirm_payment_fill
        from agent.redact import register_vault_redaction_value
        from .redaction_compat import register_context_secret
        secret, started, stage = None, False, 'preflight'
        try:
            scope_guard()
            backend = payment_backend(handle, target.origin)
            meta = backend.get_meta(handle)
            assert_target(target)
            stage = 'consent'
            # Native approved event binds BOTH merchant and provider before resolution.
            label = meta.label + '; merchant ' + target.spec['merchant_origin'] + '; provider ' + target.origin
            if not _confirm_payment_fill(label, target.origin):
                return {'success': False, 'status': 'payment_declined'}
            stage = 'revalidation'
            scope_guard()
            assert_target(target)
            backend = payment_backend(handle, target.origin)
            if backend.get_meta(handle) != meta:
                raise ValueError('card metadata changed')
            scope_guard()
            target.supervisor.check()
            target.supervisor.lease_check()
            secret = backend.resolve_secret(handle)
            register_vault_redaction_value(secret.get('card_number', ''))
            register_context_secret(secret.get('cvc', ''), kind='cvc')
            stage = 'format'
            values = values_for(target.spec, secret)
            for sid, guard, indices in target.guards:
                if indices and _invoke(target.supervisor, sid, guard, 'function(v){return this.prepare(v)}', ([values[i] for i in indices],)).get('value') is not True:
                    raise ValueError('card fields refused')
            destinations = {i: (sid, guard, j) for sid, guard, indices in target.guards for j, i in enumerate(indices)}
            for i, value in enumerate(values):
                sid, guard, local = destinations[i]
                stage = 'focus'
                scope_guard()
                assert_target(target)
                if _invoke(target.supervisor, sid, guard, 'function(i){return this.focus(i)}', (local,)).get('value') is not True:
                    raise ValueError('card focus changed')
                scope_guard()
                assert_target(target)
                stage = 'write'
                started = True
                result = _invoke(target.supervisor, sid, guard, 'function(i,v){return this.write(i,v)}', (local, value)).get('value')
                if result != {'written': True, 'valid': True}:
                    raise ValueError('card write unconfirmed')
                scope_guard()
                assert_target(target)
            return {'success': True, 'status': 'filled', 'filled_fields': len(values), 'origin': target.origin, 'kind': 'payment'}
        except Exception:
            return {'success': False, 'status': 'unknown' if started else 'target_refused', 'stage': stage}
        finally:
            if secret is not None:
                secret.clear()
