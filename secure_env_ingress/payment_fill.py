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
from .bound_cdp import BoundCDP


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
  const presentation=new Set(nodes), labelRoots=new Set();
  for(const n of nodes) {
    for(const label of [...Array.from(n.labels || []), ...(n.getAttribute('aria-labelledby') || '')
      .split(/\s+/).filter(Boolean).map(id=>doc.getElementById(id)).filter(Boolean)]) {
      labelRoots.add(label);
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
  const slots=new Map();
  const decorationSafe=()=> {
    const decoded=selector=>selector.replace(/\/\*[\s\S]*?\*\//g,'')
      .replace(/\\([0-9a-f]{1,6})\s?|\\([^\r\n])/gi,(_,hex,char)=>hex ? String.fromCodePoint(parseInt(hex,16) || 0xfffd) : char);
    // Effects on display:none icons may compute as none until briefly shown.
    // Deny stylesheet motion/paint effects rather than trusting final geometry.
    const effectsSafe=s=>!s || boundedPaint(s) && ['transform','translate','rotate','scale','filter','backdrop-filter','box-shadow','animation-name','offset-path']
      .every(k=>!s.getPropertyValue(k) || s.getPropertyValue(k)==='none') &&
      (!s.getPropertyValue('zoom') || ['1','normal'].includes(s.getPropertyValue('zoom'))) &&
      (!s.getPropertyValue('transition-duration') || /^0s(?:,\s*0s)*$/.test(s.getPropertyValue('transition-duration')));
    // Legacy strict-SPAN policy is unchanged. The reserved-slot policy scopes
    // paint/motion rules to possible decoration/ancestor matches, not unrelated
    // Bootstrap widgets. Strip state predicates to include latent :hover/focus
    // rules; relational/attribute selectors and opaque/scope/container CSS still
    // fail globally. Unknown selector syntax fails closed for effect rules.
    const relevantEffects=r=> {
      if(!slots.size || icons.size) return effectsSafe(r.style);
      if(!r.style || !r.selectorText) return true; // keyframes require a denied animation-name
      const branches=r.selectorText.split(/,(?![^()]*\))/);
      if(branches.length>1) return branches.every(selectorText=>relevantEffects({style:r.style,selectorText}));
      const selector=decoded(r.selectorText).replace(/:not\([^()]*\)/gi,'')
        .replace(/::?[\w-]+(?:\([^()]*\))?/g,'').replace(/(^|,)\s*(?=,|$)/g,'$1 *');
      const candidates=new Set();
      for(const [e,s] of slots) for(const a of [...chain(e),s.image]) if(a.nodeType===1) candidates.add(a);
      try {
        // Resolve protected-state authority before any property or role exception.
        // Activation and custom properties can expose an already oversized subject.
        const raw=decoded(r.selectorText);
        const stateBearing=s=>s.replace(/::[\w-]+(?:\([^()]*\))?/g,'')
          .replace(/:(?:root|before|after|first-letter|first-line|first-child|last-child|only-child|first-of-type|last-of-type|only-of-type)\b/gi,'')
          .replace(/:(?:nth-child|nth-last-child|nth-of-type|nth-last-of-type|lang|dir)\([^:()]*\)/gi,'').includes(':');
        const dynamic=stateBearing(raw);
        let subjects;
        const allSubjects=()=>subjects ||= Array.from(doc.querySelectorAll(selector));
        let dependent=dynamic && Array.from(protectedNodes).some(e=>e.nodeType===1 && e.matches(selector));
        if(dynamic) for(const m of raw.matchAll(/\([^()]*\)|\[[^\]]*\]|(\s*[>+~]\s*|\s+)/g)) {
          if(!m[1]) continue;
          const prefix=raw.slice(0,m.index).trim();
          if(!stateBearing(prefix)) continue;
          const possible=prefix.replace(/:not\([^()]*\)/gi,'').replace(/::?[\w-]+(?:\([^()]*\))?/g,'').trim() || '*';
          if(Array.from(protectedNodes).some(e=>e.nodeType===1 && e.matches(possible))) dependent=true;
        }
        if(dependent && Array.from(r.style).some(k=>
          k.startsWith('--') || /\b(?:var|env)\s*\(/i.test(r.style.getPropertyValue(k)))) return false;
        const matching=Array.from(candidates).filter(e=>e.matches(selector));
        if(matching.length) {
          if(dependent && !allSubjects().every(e=>candidates.has(e))) return false;
          if(!effectsSafe(r.style)) return false;
          for(const e of matching) {
            const entry=slots.get(e) || Array.from(slots.values()).find(s=>s.image===e);
            if(!entry) {
              // Immutable ancestors may lay out the form, but latent state rules
              // must not resize/reposition it between checks and then revert.
              if(dynamic && Array.from(r.style).some(k=>/^(?:display|position|inset|top|right|bottom|left|width|height|min-|max-|margin|padding|border|overflow|flex|grid|contain)/.test(k))) return false;
              continue;
            }
            const image=e===entry.image,cs=getComputedStyle(e),w=entry.image.naturalWidth,h=entry.image.naturalHeight;
            for(const k of r.style) {
              const v=r.style.getPropertyValue(k);
              if(['width','height'].includes(k) && !['auto',(k==='width' ? w : h)+'px'].includes(v)) return false;
              if(['min-width','min-height'].includes(k) && !['auto','0px','0'].includes(v)) return false;
              if(['max-width','max-height'].includes(k) && v!=='none') return false;
              if(['left','bottom'].includes(k) && v!=='auto') return false;
              if(['top','right'].includes(k) && v!==cs.getPropertyValue(k)) return false;
              if(k==='display' && !(image ? ['inline','block'] : ['none','flex']).includes(v)) return false;
              if(k==='position' && v!==(image ? 'static' : 'absolute')) return false;
              if(/^(?:margin|padding|border)(?:-|$)/.test(k) && !/^(?:0(?:px)?|none)$/.test(v)) return false;
              if(/^(?:flex|grid|inset|contain|overflow|content|order|float|z-index)/.test(k)) return false;
            }
          }
          return true;
        }
        if(nodes.some(e=>e.matches(selector))) {
          if((dependent || !effectsSafe(r.style)) && !allSubjects().every(e=>nodes.includes(e))) return false;
          if(/:/.test(decoded(r.selectorText)) && Array.from(r.style).some(k=>
            /^(?:display|position|inset|top|right|bottom|left|width|height|min-|max-|margin|padding|overflow|flex|grid|contain)/.test(k) || (/^border-(?:top|right|bottom|left)-width$/.test(k) && r.style.getPropertyValue(k)!=='1px'))) return false;
          // Inset input paint and border/shadow transitions do not move setters
          // or resize boxes. Other motion on controls remains unsupported.
          if((r.style.getPropertyValue('outline-style') && r.style.getPropertyValue('outline-style')!=='none') ||
             (r.style.getPropertyValue('outline-width') && !['0px','0','initial'].includes(r.style.getPropertyValue('outline-width')))) return false;
          return ['transform','translate','rotate','scale','filter','backdrop-filter','animation-name','offset-path']
            .every(k=>!r.style.getPropertyValue(k) || r.style.getPropertyValue(k)==='none') &&
            (!r.style.getPropertyValue('zoom') || ['1','normal'].includes(r.style.getPropertyValue('zoom'))) &&
            (!r.style.getPropertyValue('box-shadow') ||
              /^rgba\(0, 0, 0, 0\.04\) 0px 2px 0px 0px inset$/.test(r.style.getPropertyValue('box-shadow'))) &&
            (!r.style.getPropertyValue('transition-property') || r.style.getPropertyValue('transition-property')
              .split(',').every(k=>['border-color','box-shadow'].includes(k.trim())));
        }
        // Descendants remain classifier/identity authority, but do not inherit
        // the geometrically bounded floating-label paint exception.
        const labels=Array.from(labelRoots).filter(e=>!nodes.includes(e));
        if(labels.some(e=>e.matches(selector))) {
          if((dependent || !effectsSafe(r.style)) && !allSubjects().every(e=>labels.includes(e))) return false;
          if(/:/.test(decoded(r.selectorText)) && Array.from(r.style).some(k=>
            (/^(?:display|position|inset|right|bottom|left|width|height|min-|max-|margin|padding|border|overflow|flex|grid|contain)/.test(k)) || (k==='top' && r.style.top!=='8px'))) return false;
          if(r.style.opacity && r.style.opacity!=='1') return false;
          return ['translate','rotate','scale','filter','backdrop-filter','box-shadow','animation-name','offset-path']
            .every(k=>!r.style.getPropertyValue(k) || r.style.getPropertyValue(k)==='none') &&
            (!r.style.getPropertyValue('transform') || ['none','translateY(-0.25rem) scale(0.75)'].includes(r.style.getPropertyValue('transform'))) &&
            (!r.style.getPropertyValue('zoom') || ['1','normal'].includes(r.style.getPropertyValue('zoom'))) &&
            (!r.style.getPropertyValue('transition-property') || r.style.getPropertyValue('transition-property').split(',').every(k=>['transform','opacity'].includes(k.trim()))) &&
            (!r.style.getPropertyValue('transition-duration') || r.style.getPropertyValue('transition-duration').split(',').every(k=>['0s','0.15s'].includes(k.trim())));
        }
        if(!dependent) return true; // unrelated widget effects remain out of scope
        // Only ordinary paint on the actual provider's normal-flow button is
        // supported outside protected roles. No variables, activation, motion or
        // unknown subjects inherit a capability from this cosmetic exception.
        const neutral={'background-image':'none','background-position-x':'0%',
          'background-position-y':'0%','background-size':'auto','background-repeat':'repeat',
          'background-attachment':'scroll','background-origin':'padding-box',
          'background-clip':'border-box','box-shadow':'none'};
        return allSubjects().length>0 && !/::/.test(raw) && allSubjects().every(e=> {
          if(e.tagName!=='BUTTON' || !e.classList.contains('custom-button-red') ||
             !e.form || !nodes.some(n=>n.form===e.form) || e.children.length || !noPseudo(e)) return false;
          const s=getComputedStyle(e),b=e.getBoundingClientRect(),f=e.form.getBoundingClientRect();
          const range=doc.createRange();range.selectNodeContents(e);
          const text=range.getBoundingClientRect();
          return ['static','relative'].includes(s.position) && boundedPaint(s) &&
            s.outlineStyle==='none' && s.textShadow==='none' && s.webkitTextStrokeWidth==='0px' &&
            (!e.textContent.trim() || (text.left>=b.left-1 && text.right<=b.right+1 && text.top>=b.top-1 && text.bottom<=b.bottom+1)) &&
            ['transform','translate','rotate','scale','filter','backdropFilter','boxShadow','offsetPath','animationName']
              .every(k=>s[k]==='none') && ['1','normal'].includes(s.zoom) &&
            b.width>0 && b.width<=Math.min(f.width,doc.defaultView.innerWidth) && b.height>0 && b.height<=64 &&
            b.left>=f.left-1 && b.right<=f.right+1 && b.top>=f.top-1 && b.bottom<=f.bottom+1;
        }) && Array.from(r.style).every(k=> {
          const v=r.style.getPropertyValue(k);
          return ['color','background-color'].includes(k) ? CSS.supports('color',v) && !/^(?:inherit|initial|unset|revert)/.test(v) :
            Object.hasOwn(neutral,k) && (v===neutral[k] || v==='initial');
        });
      } catch {return false;}
    };
    const safe=rules=>Array.from(rules).every(r=> relevantEffects(r) &&
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
  // Additive DIV+IMG contract: immutable absolute decoration entirely inside
  // an existing selected input's right-padding reserve. Intrinsic image size
  // bounds hidden paint; no temporary display/style probes touch the provider.
  // This does NOT grant arbitrary DIVs a restyling or normal-flow exception.
  const slotInline=text=> {
    const s=doc.createElement('div').style;s.cssText=text || '';
    if(Array.from(s).some(k=>k!=='display') || s.getPropertyPriority('display') ||
       !['','none','flex'].includes(s.display)) return false;
    return true;
  };
  const inert=e=>!e.hasAttribute('tabindex') && !e.hasAttribute('contenteditable') &&
    !e.hasAttribute('role') && !Array.from(e.attributes).some(a=>/^on/i.test(a.name));
  const noPseudo=e=>['::before','::after'].every(p=>['none','normal'].includes(getComputedStyle(e,p).content));
  const zeroEdges=s=>['marginTop','marginRight','marginBottom','marginLeft','paddingTop','paddingRight','paddingBottom','paddingLeft',
    'borderTopWidth','borderRightWidth','borderBottomWidth','borderLeftWidth'].every(k=>s[k]==='0px');
  // Rectangles and ordinary border widths do not bound border-image outsets
  // or Chromium reflections. Check both computed and latent declarations.
  const boundedPaint=s=>['border-image-source','-webkit-box-reflect'].every(k=>
    !s.getPropertyValue(k) || s.getPropertyValue(k)==='none') &&
    (!s.getPropertyValue('border-image-outset') || /^0(?:px)?(?:\s+0(?:px)?)*$/.test(s.getPropertyValue('border-image-outset')));
  const slotBox=(e,n,image)=> {
    const h=n.parentElement,s=getComputedStyle(e),is=getComputedStyle(image),hs=getComputedStyle(h),ns=getComputedStyle(n);
    const w=image.naturalWidth,t=image.naturalHeight;
    const dimension=(v,size)=>v==='auto' || v===size+'px';
    if(e.tagName!=='DIV' || image.tagName!=='IMG' || e.children.length!==1 || e.firstElementChild!==image ||
       Array.from(e.childNodes).some(c=>c.nodeType===3 && c.textContent.trim()) || image.childNodes.length ||
       !image.complete || !image.currentSrc || !Number.isInteger(w) || !Number.isInteger(t) ||
       w<=0 || t<=0 || w>64 || t>64 || !inert(e) || !inert(image) || !noPseudo(e) || !noPseudo(image) ||
       e.parentElement!==h || !['none','flex'].includes(s.display) || s.position!=='absolute' ||
       !zeroEdges(s) || !zeroEdges(is) || !noEffects(s) || !noEffects(is) || !boundedPaint(s) || !boundedPaint(is) ||
       s.visibility!=='visible' || s.opacity!=='1' || s.contentVisibility!=='visible' ||
       is.visibility!=='visible' || is.opacity!=='1' || is.contentVisibility!=='visible' ||
       !dimension(s.width,w) || !dimension(s.height,t) || !dimension(is.width,w) || !dimension(is.height,t) ||
       !['0px','auto'].includes(s.minWidth) || !['0px','auto'].includes(s.minHeight) || s.maxWidth!=='none' || s.maxHeight!=='none' ||
       !['0px','auto'].includes(is.minWidth) || !['0px','auto'].includes(is.minHeight) || is.maxWidth!=='none' || is.maxHeight!=='none' ||
       (s.display==='none' && s.bottom!=='auto') || !/^\d+(?:\.\d+)?px$/.test(s.right) || !/^\d+(?:\.\d+)?px$/.test(s.top) ||
       hs.position!=='relative' || !zeroEdges(hs) || chain(h).some(a=>a.nodeType===1 && !noEffects(getComputedStyle(a))) ||
       is.position!=='static' || is.cssFloat!=='none' || s.cssFloat!=='none' ||
       !['auto','0'].includes(s.zIndex) || !['auto','0'].includes(is.zIndex)) return null;
    const hr=h.getBoundingClientRect(),nr=n.getBoundingClientRect();
    const x=hr.right-parseFloat(s.right)-w,y=hr.top+parseFloat(s.top);
    const box={left:x,right:x+w,top:y,bottom:y+t,width:w,height:t};
    // Only the input border/padding area may overlap; never its editable text
    // rectangle or any other protected control/label. No pointer filling occurs.
    if(x<nr.right-parseFloat(ns.paddingRight) || box.right>nr.right-parseFloat(ns.borderRightWidth) ||
       y<nr.top+parseFloat(ns.borderTopWidth) || box.bottom>nr.bottom-parseFloat(ns.borderBottomWidth) ||
       Array.from(presentation).filter(p=>p!==n).some(p=>Array.from(p.getClientRects()).some(q=>
         q.width && q.height && box.right>q.left && box.left<q.right && box.bottom>q.top && box.top<q.bottom))) return null;
    if(s.display==='flex') {
      const r=e.getBoundingClientRect(),ir=image.getBoundingClientRect();
      if([r,ir].some(r=>r.left!==x || r.top!==y || r.width!==w || r.height!==t)) return null;
    } else if(s.left!=='auto') return null;
    return JSON.stringify(box);
  };
  if(!strictMutations) for(const n of nodes) for(const e of n.parentElement?.children || []) {
    const image=e.firstElementChild;
    if(!protectedNodes.has(e) && image && slotInline(e.getAttribute('style')) && slotBox(e,n,image)) {
      slots.set(e,{input:n,image,source:image.currentSrc,imageAttrs:attrs(image),seenStyle:e.hasAttribute('style'),
        attributes:JSON.stringify(Array.from(e.attributes,a=>[a.name,a.value]).filter(a=>a[0]!=='style')),
        box:slotBox(e,n,image),path:chain(e)});
      // IMG mutations are not exception targets: the observer rejects every
      // attribute/topology change, while its computed flex-item display may vary.
    }
  }
  const authority=Array.from(protectedNodes,e=>({e,attributes:attrs(e),style:style(e)}));
  // Floating noninteractive labels may change visual geometry through immutable
  // focus/placeholder CSS. Retained nodes, semantics and visibility stay bound.
  // Controls/wrappers never get that exception; the legacy SPAN contract remains.
  const positions=hosts.size ? Array.from(presentation,e=>({e,geometry:geometry(e)})) :
    slots.size ? Array.from(new Set(nodes.flatMap(n=>[n,n.parentElement])),e=>({e,geometry:geometry(e)})) : [];
  const cssIdentity=()=> {
    const rows=s=>{try{return [s.href,Array.from(s.cssRules,r=>[r.cssText,r.styleSheet ? rows(r.styleSheet) : null])];}catch{return ['opaque'];}};
    return JSON.stringify([...Array.from(doc.styleSheets),...Array.from(doc.adoptedStyleSheets || [])].map(rows));
  };
  const cssAtBinding=slots.size ? cssIdentity() : null;
  // State-stripped selectors and immutable CSS/DOM authority make this verdict
  // visibility-independent. Cache the costly recursive analysis; do not scan
  // thousands of Bootstrap rules once per mutation within a bounded CDP call.
  const slotCssSafe=slots.size ? decorationSafe() : null;
  const labelsWithinControls=()=>nodes.every(n=>Array.from(n.labels || []).every(l=>{
    const s=getComputedStyle(l),r=l.getBoundingClientRect(),b=n.getBoundingClientRect();
    return s.position==='absolute' && s.pointerEvents==='none' && noPseudo(l) &&
      r.left>=b.left && r.right<=b.right && r.top>=b.top && r.bottom<=b.bottom;
  }));
  let changed=false;
  const observe=records=> {
    for(const r of records) {
      // No child-list draining/bypass: even remove+reattach fails permanently.
      // Style sheets, labels, control semantics and all topology stay strict.
      // Chromium can lose a lazily serialized CSSOM oldValue on removal.
      // Only the first style creation may have a null witness; removals and
      // remove/recreate batches are not display toggles and stay sticky.
      if(r.type==='attributes' && r.attributeName==='style' && slots.has(r.target)) {
        const s=slots.get(r.target);
        if(r.oldValue===null && s.seenStyle) changed=true;
        s.seenStyle=true;
      }
      const unrelated=r.type==='attributes' && !protectedNodes.has(r.target);
      const safeStyle=unrelated && r.attributeName==='style' && (
        (icons.has(r.target) && inlineIconStyle(r.oldValue)===icons.get(r.target).baseline &&
          inlineIconStyle(r.target.getAttribute('style'))===icons.get(r.target).baseline &&
          boundedIcon(r.target,icons.get(r.target).host)) ||
        (slots.has(r.target) && r.target.getAttribute('style')!==null &&
          ['none','flex'].includes(r.target.style.display) &&
          slotInline(r.oldValue) && slotInline(r.target.getAttribute('style'))));
      const safeHidden=unrelated && r.attributeName==='value' &&
        r.target.tagName==='INPUT' && r.target.type==='hidden';
      if(strictMutations || (!safeStyle && !safeHidden) || !(slots.size ? slotCssSafe : decorationSafe())) changed=true;
    }
  };
  const observer=new MutationObserver(observe);
  observer.observe(doc,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true});
  const equal=(a,b)=>a.length===b.length && a.every((e,i)=>e===b[i]);
  const valid=()=> {
    observe(observer.takeRecords());
    if(slots.size && (cssIdentity()!==cssAtBinding || !labelsWithinControls())) changed=true;
    return !changed && document===doc && location.href===href && self.origin===origin &&
      authority.every(s=>attrs(s.e)===s.attributes && style(s.e)===s.style) &&
      positions.every(s=>geometry(s.e)===s.geometry) &&
      Array.from(slots,([e,s])=>e.isConnected && equal(chain(e),s.path) &&
        s.image===e.firstElementChild && s.source===s.image.currentSrc && s.imageAttrs===attrs(s.image) &&
        s.attributes===JSON.stringify(Array.from(e.attributes,a=>[a.name,a.value]).filter(a=>a[0]!=='style')) &&
        slotInline(e.getAttribute('style')) && slotBox(e,s.input,s.image)===s.box).every(Boolean) &&
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
  // Sticky event-time readback catches a changed adopted value even if a later
  // callback restores it before CDP returns. No events are emitted by adoption.
  const valueEvent=()=>{if(!Array.from(filled,([i,f])=>matches(nodes[i],f.value,f.token)).every(Boolean)) changed=true;};
  for(const event of ['input','change','focus','blur']) doc.addEventListener(event,valueEvent,true);
  return Object.freeze({valid, close:()=>{
    observer.disconnect();
    for(const event of ['input','change','focus','blur']) doc.removeEventListener(event,valueEvent,true);
  },
    prepare:(fills,resume)=>{
      if(!valid() || fills.length!==nodes.length) return false;
      if(!resume) return [];
      const adopted=[];
      for(let i=0;i<nodes.length;i++) {
        const e=nodes[i], f=fills[i];
        if(e.value!=='') {
          if(!resume || !matches(e,f.value,f.token) || (f.token==='cc-number' && e.hasAttribute('data-pkn'))) return false;
          adopted.push(i);
        }
      }
      for(const i of adopted) filled.set(i,{value:fills[i].value,token:fills[i].token});
      return valid() ? adopted : false;
    },
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


def classify_payment_control(control):
    """Keep native authority; recognize only the missing Computop identity."""
    from agent.vault_login_classifier import classify_checkout_control, ClassifiedLoginControl
    native = classify_checkout_control(control)
    if native is not None:
        return native
    if (control.form_index is not None and control.type == 'text'
            and control.name == 'creditCardHolder creditCardHolder' and control.label.strip() == 'Card holder*'
            and control.autocomplete.strip().lower() in ('', 'off')):
        return ClassifiedLoginControl(control, 70, 'cc-name')
    return None


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
        root = _call(sup, 'DOM.getDocument', {'depth': 0}, psid)['result']['root']['nodeId']
        owners = _call(sup, 'DOM.querySelectorAll', {'nodeId': root, 'selector': 'iframe,frame'}, psid)['result']['nodeIds']
        if len(owners) > 20:
            raise ValueError('too many frames')
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
                    c = classify_payment_control(LoginControl.from_dict(row))
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
        return targets
    except BaseException:
        for t in targets:
            release(t)
        raise
    finally:
        parent_session.drop(None)


def assert_target(target):
    sup = _supervisor(target.task)
    parent_sid = target.parent_session.check() if target.parent_session is not None else _parent(sup, target.parent)
    if sup is not getattr(target.supervisor, 'raw', target.supervisor) or time.monotonic() >= target.expires or parent_sid != target.parent_sid:
        raise ValueError('stale target')
    sup = target.supervisor
    # getFrameOwner resolves only in the selected parent document's session;
    # the exact remote owner/document closures reject detach and reparenting.
    if _call(sup, 'DOM.getFrameOwner', {'frameId': target.frame}, target.parent_sid)['result']['backendNodeId'] != target.owner_node:
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
    for sid, obj in ((target.parent_sid, target.parent_guard), (target.child_sid, target.child_guard)):
        _close_object(target.supervisor, sid, obj)
    if target.attachment is not None:
        target.attachment.drop(target.child_guard)
    if target.parent_session is not None:
        target.parent_session.drop(target.parent_guard)


def approved_fill(target, handle, scope_guard, resume_existing=False):
    from tools.browser_vault_tool import _confirm_payment_fill, _bot_desktop_browser_session
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
        if not _confirm_payment_fill(meta.label, target.origin):
            return {'success': False, 'status': 'payment_declined'}
        stage = 'revalidation'
        scope_guard()
        assert_target(target)
        approved_meta = meta
        backend = payment_backend(handle, target.origin)
        if backend.get_meta(handle) != approved_meta:
            raise ValueError('payment metadata changed')
        stage = 'mapping'
        secret = backend.resolve_secret(handle)
        fills = mapped_fills(target.controls, secret)
        for value in secret.values():
            register_vault_redaction_value(value)
        # Register derived expiry as well as raw fields before page contact.
        for f in fills:
            register_vault_redaction_value(f['value'])
        sup, sid, obj = target.supervisor, target.child_sid, target.child_guard
        stage = 'format'
        for i, f in enumerate(fills):
            if _invoke(sup, sid, obj, 'function(i,v,token){return this.accepts(i,v,token);}', (i, f['value'], f['token'])) is not True:
                raise ValueError('unsupported field format')
        stage = 'existing'
        adopted = _invoke(sup, sid, obj, 'function(fills,resume){return this.prepare(fills,resume);}', (fills, resume_existing))
        if not isinstance(adopted, list) or any(type(i) is not int or not 0 <= i < len(fills) for i in adopted):
            raise ValueError('existing field refused')
        filled = len(adopted)
        for i, f in enumerate(fills):
            if i in adopted:
                continue
            stage = 'focus'
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
            stage = 'write'
            started = True
            result = _invoke(sup, sid, obj, 'function(i,v,token){return this.write(i,v,token);}', (i, f['value'], f['token']))
            if not isinstance(result, dict) or not result.get('written') or not result.get('valid'):
                raise ValueError('write not confirmed')
            filled += 1
            scope_guard()
            assert_target(target)
        stage = 'completion'
        scope_guard()
        assert_target(target)
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

    def choose(self, scope, task, parent, origin, handle, selection=None, *, batch=None):
        from .bound_cdp import acquisition_scope
        batch = batch if batch is not None else threading.Event()
        with self._lock:
            if self._closed or batch.is_set():
                raise ValueError('selection stopped')
            now = time.monotonic()
            self._drop([k for k, v in self._entries.items() if v[0] <= now])
            binding = (task, parent, origin, handle)
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
            targets = discover(task, parent, origin)
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
