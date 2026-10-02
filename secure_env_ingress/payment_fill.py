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


# takeRecords closes the observer-microtask gap; sticky mutation classification
# rejects protected changes even if reverted. Only prebound bounded icon display
# and unrelated hidden-value attributes are allowed. Inspection stays strict.
# Exact identities, ancestry, attributes and relevant computed styles are kept
# in isolated-world closures; filled values never cross back into Python/model.
_GUARD = r'''function(nodes, inspection=false, strictMutations=inspection) {
  const doc=document, href=location.href, origin=self.origin;
  const chain=e => { const a=[]; for(;e;e=e.parentNode) a.push(e); return a; };
  const attrs=e => e.attributes ? JSON.stringify(Array.from(e.attributes,a=>[a.name,a.value])) : '';
  const snapshots=nodes.map(e=>({e, path:chain(e), form:e.form,
    formPath:e.form ? chain(e.form) : [], attributes:attrs(e),
    formAttrs:e.form ? attrs(e.form) : ''}));
  const protectedNodes=new Set();
  for(const s of snapshots) {
    for(const e of [...s.path,...s.formPath]) protectedNodes.add(e);
    // Labels/ARIA references are classifier authority, including descendants.
    const labels=[...Array.from(s.e.labels || []), ...(s.e.getAttribute('aria-labelledby') || '')
      .split(/\s+/).filter(Boolean).map(id=>doc.getElementById(id)).filter(Boolean)];
    for(const label of labels) {
      for(const e of chain(label)) protectedNodes.add(e);
      protectedNodes.add(label);
      for(const e of label.querySelectorAll('*')) protectedNodes.add(e);
    }
  }
  const style=e=> {
    if(e.nodeType!==1) return '';
    const s=getComputedStyle(e);
    return JSON.stringify([s.display,s.visibility,s.opacity,s.pointerEvents,s.contentVisibility]);
  };
  // Host authority must be added before taking immutable snapshots below.
  const presentation=new Set(nodes);
  for(const n of nodes) {
    for(const label of [...Array.from(n.labels || []), ...(n.getAttribute('aria-labelledby') || '')
      .split(/\s+/).filter(Boolean).map(id=>doc.getElementById(id)).filter(Boolean)]) {
      presentation.add(label);
      for(const e of label.querySelectorAll('*')) presentation.add(e);
    }
  }
  const filled=new Map();
  const matches=(e,v,token)=> token==='cc-number' ?
    /^[0-9]+$/.test(v) && /^[0-9]+(?: [0-9]+)*$/.test(e.value) && e.value.replace(/ /g,'')===v : e.value===v;
  // Sibling attributes can influence protected controls through relational CSS.
  // Refuse the exception if styles are opaque or contain attribute-sensitive
  // selectors; checking only final computed style would miss reverted attacks.
  const decorationSafe=()=> {
    const decoded=selector=>selector.replace(/\/\*[\s\S]*?\*\//g,'')
      .replace(/\\([0-9a-f]{1,6})\s?|\\([^\r\n])/gi,(_,hex,char)=>hex ? String.fromCodePoint(parseInt(hex,16) || 0xfffd) : char);
    // Effects on display:none icons may compute as none until briefly shown.
    // Deny stylesheet motion/paint effects rather than trusting final geometry.
    const effectsSafe=s=>!s || ['transform','translate','rotate','scale','filter','backdrop-filter','box-shadow','animation-name','offset-path']
      .every(k=>!s.getPropertyValue(k) || s.getPropertyValue(k)==='none') &&
      (!s.getPropertyValue('zoom') || ['1','normal'].includes(s.getPropertyValue('zoom'))) &&
      (!s.getPropertyValue('transition-duration') || /^0s(?:,\s*0s)*$/.test(s.getPropertyValue('transition-duration')));
    const safe=rules=>Array.from(rules).every(r=> effectsSafe(r.style) &&
      // Scope root/limit selectors live in start/end, not selectorText.
      // Conservatively deny scope rules rather than guessing selector effects.
      (!('start' in r) && !('end' in r) && !('containerName' in r) &&
        !/^@container\b/i.test(r.cssText || '')) &&
      (!r.selectorText || !/:has\s*\(|\[[^\]]*\b(?:style|value)\b/i.test(decoded(r.selectorText))) &&
      (!r.cssRules || safe(r.cssRules)) && (!r.styleSheet || safe(r.styleSheet.cssRules)));
    try {return [...Array.from(doc.styleSheets),...Array.from(doc.adoptedStyleSheets || [])].every(s=>safe(s.cssRules));}
    catch {return false;}
  };
  // Discover pre-existing dedicated hosts only; never modify the site to create
  // compatibility. The host occupies immutable fixed space even when its sole
  // absolutely positioned empty icon is hidden. Hidden rects are NOT evidence:
  // min/max dimensions, offsets and margins are checked independent of display.
  const displays=new Set(['none','block']);
  const inlineIconStyle=text=> {
    const s=doc.createElement('span').style;s.cssText=text || '';
    const allowed=new Set(['display','position','box-sizing','left','top','width','height',
      'min-width','max-width','min-height','max-height','margin','margin-top','margin-right','margin-bottom','margin-left',
      'padding','padding-top','padding-right','padding-bottom','padding-left','border','border-width','border-style','border-color',
      'border-image-source','border-image-slice','border-image-width','border-image-outset','border-image-repeat',
      'pointer-events','overflow','overflow-x','overflow-y','contain',
      'background','background-image','background-position','background-size','background-repeat','background-color']);
    if(!displays.has(s.display) || s.getPropertyPriority('display') || Array.from(s).some(k=>
      !allowed.has(k) && !/^border-(?:top|right|bottom|left)-(?:width|style|color)$/.test(k))) return null;
    s.removeProperty('display');
    return JSON.stringify(Array.from(s).sort().map(k=>[k,s.getPropertyValue(k),s.getPropertyPriority(k)]));
  };
  const geometry=e=>JSON.stringify(Array.from(e.getClientRects(),r=>[r.x,r.y,r.width,r.height]));
  const fullStyle=e=> {const s=getComputedStyle(e);return JSON.stringify(Array.from(s,k=>[k,s.getPropertyValue(k)]));};
  const noEffects=s=>s.transform==='none' && s.translate==='none' && s.rotate==='none' && s.scale==='none' &&
    s.filter==='none' && s.backdropFilter==='none' && s.boxShadow==='none' && s.outlineStyle==='none' &&
    s.animationName==='none' && /^0s(?:,\s*0s)*$/.test(s.transitionDuration) && s.offsetPath==='none' &&
    ['1','normal'].includes(s.zoom) && s.mixBlendMode==='normal';
  const fixedBox=s=> {
    const px=v=>/^[0-9]+(?:\.[0-9]+)?px$/.test(v) && parseFloat(v)>0 && parseFloat(v)<=64;
    return px(s.width) && px(s.height) && s.minWidth===s.width && s.maxWidth===s.width &&
      s.minHeight===s.height && s.maxHeight===s.height && s.boxSizing==='border-box' &&
      ['marginTop','marginRight','marginBottom','marginLeft','paddingTop','paddingRight','paddingBottom','paddingLeft',
       'borderTopWidth','borderRightWidth','borderBottomWidth','borderLeftWidth'].every(k=>s[k]==='0px') &&
      s.pointerEvents==='none' && s.overflowX==='hidden' && s.overflowY==='hidden' && s.contain==='strict' &&
      s.cssFloat==='none' && s.writingMode==='horizontal-tb' && s.zIndex==='auto' && noEffects(s);
  };
  const noninteractive=e=>e.tagName==='SPAN' && !e.hasAttribute('tabindex') &&
    !e.hasAttribute('contenteditable') && !e.hasAttribute('role');
  const boundedIcon=(e,h)=> {
    const s=getComputedStyle(e), hs=getComputedStyle(h), r=h.getBoundingClientRect();
    if(!noninteractive(e) || e.childNodes.length || !noninteractive(h) || h.childNodes.length!==1 ||
       h.firstChild!==e || !displays.has(s.display) || s.position!=='absolute' || !fixedBox(s) ||
       s.left!=='0px' || s.top!=='0px' || !['auto','0px'].includes(s.right) || !['auto','0px'].includes(s.bottom) ||
       !fixedBox(hs) || hs.display!=='inline-block' && hs.display!=='block' || hs.position!=='relative' ||
       hs.visibility!=='visible' || hs.contentVisibility!=='visible' || hs.opacity!=='1' ||
       parseFloat(s.width)>parseFloat(hs.width) || parseFloat(s.height)>parseFloat(hs.height) ||
       r.width!==parseFloat(hs.width) || r.height!==parseFloat(hs.height)) return false;
    // Fixed flex contribution; grid tracks cannot resize a strict fixed min/max
    // border box. Reject motion/effects anywhere in its containing ancestry.
    if(hs.flexGrow!=='0' || hs.flexShrink!=='0' || hs.flexBasis!==hs.width) return false;
    if(chain(h).some(a=>a.nodeType===1 && !noEffects(getComputedStyle(a)))) return false;
    return Array.from(presentation).every(p=>Array.from(p.getClientRects()).every(q=>
      q.width===0 || q.height===0 || r.right<=q.left || r.left>=q.right || r.bottom<=q.top || r.top>=q.bottom));
  };
  const icons=new Map(), hosts=new Map();
  if(!strictMutations) for(const n of nodes) for(const h of n.parentElement?.children || []) {
    const e=h.firstElementChild;
    if(e && !protectedNodes.has(h) && !protectedNodes.has(e) && boundedIcon(e,h)) {
      const baseline=inlineIconStyle(e.getAttribute('style'));
      if(baseline!==null) {
        icons.set(e,{baseline,host:h});
        hosts.set(h,{path:chain(h),attributes:attrs(h),style:fullStyle(h),geometry:geometry(h)});
        for(const a of chain(h)) protectedNodes.add(a);
      }
    }
  }
  const authority=Array.from(protectedNodes,e=>({e,attributes:attrs(e),style:style(e)}));
  const positions=hosts.size ? Array.from(presentation,e=>({e,geometry:geometry(e)})) : [];
  let changed=false;
  const observe=records=> {
    for(const r of records) {
      // No child-list draining/bypass: even remove+reattach fails permanently.
      // Style sheets, labels, control semantics and all topology stay strict.
      const unrelated=r.type==='attributes' && !protectedNodes.has(r.target);
      const safeStyle=unrelated && r.attributeName==='style' && icons.has(r.target) &&
        inlineIconStyle(r.oldValue)===icons.get(r.target).baseline &&
        inlineIconStyle(r.target.getAttribute('style'))===icons.get(r.target).baseline &&
        boundedIcon(r.target,icons.get(r.target).host);
      const safeHidden=unrelated && r.attributeName==='value' &&
        r.target.tagName==='INPUT' && r.target.type==='hidden';
      if(strictMutations || (!safeStyle && !safeHidden) || !decorationSafe()) changed=true;
    }
  };
  const observer=new MutationObserver(observe);
  observer.observe(doc,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true});
  const equal=(a,b)=>a.length===b.length && a.every((e,i)=>e===b[i]);
  const valid=()=> {
    observe(observer.takeRecords());
    return !changed && document===doc && location.href===href && self.origin===origin &&
      authority.every(s=>attrs(s.e)===s.attributes && style(s.e)===s.style) &&
      positions.every(s=>geometry(s.e)===s.geometry) &&
      Array.from(hosts,([h,s])=>h.isConnected && equal(chain(h),s.path) && attrs(h)===s.attributes &&
        fullStyle(h)===s.style && geometry(h)===s.geometry).every(Boolean) &&
      Array.from(icons,([e,s])=>e.parentElement===s.host && boundedIcon(e,s.host)).every(Boolean) &&
      Array.from(filled,([i,f])=>matches(nodes[i],f.value,f.token)).every(Boolean) &&
      snapshots.every(s => s.e.isConnected && equal(chain(s.e),s.path) &&
        attrs(s.e)===s.attributes && s.e.form===s.form &&
        (!s.form || (s.form.isConnected && attrs(s.form)===s.formAttrs && equal(chain(s.form),s.formPath))) &&
        (inspection || (!s.e.disabled && !s.e.matches(':disabled') && !s.e.readOnly && s.e.getClientRects().length &&
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
    write:(i,v,token)=>{if(!valid() || !doc.hasFocus() || doc.activeElement!==nodes[i]) return {written:false,valid:false}; const e=nodes[i];
      (e.tagName==='SELECT' ? selectSetter : inputSetter).call(e,v);
      if(!matches(e,v,token)) return {written:true,valid:false};
      filled.set(i,{value:v,token});
      e.dispatchEvent(new Event('input',{bubbles:true}));
      if(!valid()) return {written:true,valid:false};
      e.dispatchEvent(new Event('change',{bubbles:true}));
      return {written:true,valid:valid()};}
  });
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
            result = _invoke(sup, sid, obj, 'function(i,v,token){return this.write(i,v,token);}', (i, f['value'], f['token']))
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
