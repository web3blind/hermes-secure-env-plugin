"""Explicit, geometry-independent native-card targets. No secret tool arguments.

Selectors describe discovery. Native-style DOM stamps, not selector history or
visual layout, choose the setter destinations in retained parent documents.
"""
from dataclasses import dataclass, field
import json
import re
import time
import unicodedata

from .vault_ingress import strict_origin
from .native_fill import BOUNDARY_JS
from .bound_cdp import BoundCDP
from .exact_code import PLAIN_EDITOR_JS
from agent.vault_login_classifier import PAYMENT_AUTOFILL_TOKENS


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
    if not isinstance(fields, list) or not 1 <= len(fields) <= 23:
        raise ValueError('invalid card target')
    for f in fields:
        if not isinstance(f, dict) or set(f) not in ({'role', 'selector', 'frame', 'format'}, {'role', 'selector', 'frame', 'format', 'part', 'length'}):
            raise ValueError('invalid card target')
        if (f['role'] not in FORMATS or f['format'] not in FORMATS[f['role']] or
                not isinstance(f['frame'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', f['frame']) or
                not isinstance(f['selector'], str) or not 1 <= len(f['selector']) <= 256 or
                any(ord(c)<32 or ord(c)==127 for c in f['selector'])):
            raise ValueError('invalid card target')
        if 'part' in f and (f['role'] != 'pan' or f['format'] != 'digits' or
                            type(f['part']) is not int or type(f['length']) is not int or not 1 <= f['length'] <= 19):
            raise ValueError('invalid card target')
    roles = [f['role'] for f in fields]
    if any(roles.count(role)>1 for role in FORMATS if role!='pan'):
        raise ValueError('duplicate card role')
    pan = [f for f in fields if f['role'] == 'pan']
    if not pan:
        pass  # Native checkout may fill only the saved roles present on this page.
    elif len(pan) == 1 and 'part' not in pan[0]:
        pass
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
                'merchant_origin': {'type': 'string'}, 'fields': {'type': 'array', 'minItems': 1, 'maxItems': 23,
                'items': {'type': 'object', 'additionalProperties': False, 'required': ['role', 'selector', 'frame', 'format'],
                          'properties': {'role': {'type': 'string', 'enum': list(FORMATS)},
                                         'selector': {'type': 'string', 'maxLength': 256}, 'frame': {'type': 'string'},
                                         'format': {'type': 'string', 'enum': sorted({v for values in FORMATS.values() for v in values})},
                                         'part': {'type': 'integer', 'minimum': 0, 'maximum': 18},
                                         'length': {'type': 'integer', 'minimum': 1, 'maximum': 19}}}}}}


def values_for(spec, secret):
    # Storage validation belongs to the native backend. This explicit adapter
    # formats only requested roles, rather than demanding a complete card form.
    valid=secret
    pan,month,year,cvc=(valid.get(k,'') for k in ('card_number','exp_month','exp_year','cvc'))
    month=month.zfill(2) if month else month
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
 const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
 const nodes=fields.map(f=>{const matches=query(f.selector);if(matches.length!==1)throw Error('card selection');return matches[0]});
 const paymentTokens=''' + json.dumps(list(PAYMENT_AUTOFILL_TOKENS)) + r''';
 if(new Set(nodes).size!==nodes.length||nodes.some(e=>!e.matches('input,select,textarea,[contenteditable]')||e.disabled||e.readOnly||
  ['hidden','submit','button','reset','file','image','checkbox','radio'].includes(e.type)||
  ['password','email'].includes(e.type)&&!(e.autocomplete||'').toLowerCase().split(/\s+/).some(t=>paymentTokens.includes(t))))throw Error('card control');
 if(nodes.some(e=>{const s=getComputedStyle(e);return s.display==='none'||s.visibility==='hidden'||!e.getClientRects().length}))throw Error('card inspection');
 if(nodes.some(e=>e.matches('[contenteditable]')&&!(''' + PLAIN_EDITOR_JS + r''')(e,roots)))throw Error('card editor');
 const boundary=(''' + BOUNDARY_JS + r''')(roots,nodes);
 return boundary;
}'''


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
    # ParentSession already freezes the original profile/human lease epoch.
    # Replacing its transport would silently re-admit a changed epoch.
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
            actual = nc._eval(sup, sid, context, 'location.origin', True).get('value')
            fields = [(i, f) for i, f in enumerate(spec['fields']) if f['frame'] == frame or f['frame'] == 'top' and frame == root]
            if frame == root and actual != spec['merchant_origin']:
                raise ValueError('merchant mismatch')
            shadows = nc._shadow_roots(sup, sid, context)
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
                guards.append((sid, docguard, ()))
            # Complete declared layouts do not census unrelated service frames.
            if len(found) == len(spec['fields']):
                return
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
                if len(found) == len(spec['fields']):
                    return
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
            scope_guard()
            target.supervisor.check()
            target.supervisor.lease_check()
            secret = backend.resolve_secret(handle)
            register_vault_redaction_value(secret.get('card_number', ''))
            register_context_secret(secret.get('cvc', ''), kind='cvc')
            values = values_for(target.spec, secret)
            destinations = {i: (sid, guard, j) for sid, guard, indices in target.guards for j, i in enumerate(indices)}
            for i, value in enumerate(values):
                sid, guard, local = destinations[i]
                scope_guard()
                assert_target(target)
                stage = 'write'
                started = True
                result = _invoke(target.supervisor, sid, guard, 'function(i,v){return this.write(i,v)}', (local, value)).get('value')
                if result != {'written': True, 'valid': True}:
                    raise ValueError('card write unconfirmed')
                scope_guard()
            return {'success': True, 'status': 'filled', 'filled_fields': len(values), 'origin': target.origin, 'kind': 'payment'}
        except Exception:
            return {'success': False, 'status': 'unknown' if started else 'target_refused', 'stage': stage}
        finally:
            if secret is not None:
                secret.clear()
