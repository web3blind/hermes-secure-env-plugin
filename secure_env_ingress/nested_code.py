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
from .bound_cdp import BoundCDP, FrameUnavailable, GUARD_VALIDATION
from .grouped_otp import GROUP_JS


# Retained references, including composed shadow ancestry, are authority.
# Unrelated UI changes are not authority changes.
_GUARD = r'''function(nodes, inspection=false, roots=[document], selector=null, spec=null, reconcileCode=false) {
  const doc=document, href=location.href, origin=self.origin;
  const path=e=>{const p=[];for(;e;e=e.parentNode||(e instanceof ShadowRoot?e.host:null))p.push(e);return p};
  const attrs=e=>JSON.stringify(Array.from(e.attributes||[],a=>[a.name,a.value]));
  const read=e=>e.tagName==='INPUT'||e.tagName==='TEXTAREA'||e.tagName==='SELECT'?e.value:e.textContent;
  const form=e=>e.matches('input,textarea,select')?e.form:e.closest('form');
  const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
  const bindings=spec?(spec.layout==='indexed_cells'?[spec.group]:spec.fields.map(f=>f.selector)):[];
  const bound=bindings.map(s=>query(s));
  const container=spec?.layout==='indexed_cells'&&bound[0].length===1?bound[0][0]:null;
  const members=container?Array.from(container.querySelectorAll(spec.field_selector)):[];
  const saved=nodes.map(e=>({e,path:path(e),attrs:attrs(e),form:form(e),
    formAttrs:form(e)?attrs(form(e)):null,action:form(e)?.action,method:form(e)?.method}));
  const groupContainers=new Set(nodes.filter(e=>e.matches('input')&&(e.maxLength===1||(/^code-\d+$/.test(e.name)&&e.inputMode==='numeric'))).map(e=>e.parentElement));
  const groupFor=(__GROUP__);
  const candidate=nodes.length?groupFor(nodes[0]):null;
  const group=!inspection&&candidate&&!candidate.forbidden&&candidate.digits.length===nodes.length&&candidate.digits.every((e,i)=>e===nodes[i])?candidate:null;
  const extras=group?[group.canonical,...group.sources].filter(Boolean):[];
  const protectedNodes=new Set([...saved.flatMap(s=>[...s.path,s.form].filter(Boolean)),...extras.flatMap(path),...(container?path(container):[])]);
  const labels=new Set([...(group?group.sources:[]),...nodes.flatMap(e=>[...Array.from(e.labels||[]),
    ...(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>e.getRootNode().getElementById(id)).filter(Boolean)])]);
  for(const l of labels){protectedNodes.add(l);for(const n of path(l))protectedNodes.add(n)}
  // MutationObserver does not cross shadow boundaries. Observe every composed
  // ancestry root, not only the iframe's immediate root and document.
  for(const n of protectedNodes){const root=n.getRootNode();if(!roots.includes(root))roots.push(root)}
  const selected=selector===null?[]:roots.flatMap(r=>Array.from(r.querySelectorAll(selector)));
  const snapshots=Array.from(protectedNodes,n=>[n,attrs(n)]);
  let completed=false;
  const touches=n=>Array.from(protectedNodes).some(p=>n===p||(n.contains&&n.contains(p)));
  const base=n=>n.nodeType===1&&(n.matches('base[href]')||n.querySelector('base[href]'));
  // Discovery uses the native classifier. Conservative semantic potential is
  // a refusal-only superset, including transient/reverted changes; never admission.
  const codeText=v=>/код/i.test(v||'')||/(?:\b(?:code|pin|token|otp|totp|2fa|mfa|passcode)\b|sms[ _-]*code)/i.test(String(v||'').normalize('NFKD').replace(/[^a-z0-9]+/gi,' '));
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
  const linkRoots=new WeakMap();
  const groupPotential=n=>n.nodeType===1&&n.querySelector('input')&&(
    Array.from(n.attributes,a=>a.value).some(codeText)||
    (n.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).some(id=>
      codeText((linkRoots.get(n)||n.getRootNode()).getElementById?.(id)?.textContent)));
  const authority=n=>n.nodeType===1&&(base(n)||semantic(n)||labelTouches(n)||selectorTouches(n)||groupPotential(n)||
    Array.from(n.querySelectorAll('*')).some(e=>semantic(e)||groupPotential(e)||labelTouches(e)));
  const sources=new Set(), sourceIds=new Map();
  const collectSources=()=>{
    for(const root of roots){
      if(!sourceIds.has(root))sourceIds.set(root,new Set());
      for(const e of root.querySelectorAll('[aria-labelledby]')){
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
    const root=linkRoots.get(r.target)||r.target.getRootNode(), ids=sourceIds.get(root)||new Set();
    if(r.attributeName==='id'){
      if(![r.oldValue,r.target.id].some(id=>id&&ids.has(id)))return false;
      sources.add(r.target);return codeText(r.target.textContent);
    }
    if(!r.target.hasAttribute('aria-labelledby')&&r.attributeName!=='aria-labelledby')return false;
    for(const id of [r.oldValue,r.target.getAttribute('aria-labelledby')].flatMap(v=>String(v||'').split(/\s+/).filter(Boolean))){
      ids.add(id);const source=root.getElementById(id);if(source){sources.add(source);if(codeText(source.textContent))return true;}
    }
    sourceIds.set(root,ids);return false;
  };
  sourceRelated(doc);
  const inLabel=n=>Array.from(labels).some(l=>l===n||l.contains(n));
  const relevant=r=>r.type==='attributes'?(protectedNodes.has(r.target)||(r.target.matches('input')&&groupContainers.has(r.target.parentElement))||inLabel(r.target)||sourceAttribute(r)||
    // An unrelated iframe's tab-order bookkeeping is not OTP authority.
    // Retained frame owners still refuse above; selector/spec paths stay conservative.
    (r.target.matches('base')&&r.attributeName==='href')||
    (semantic(r.target)&&!(selector===null&&r.attributeName==='tabindex'&&r.target.matches('iframe,frame')))||
    ((r.target.matches('input,select,label')||r.target.querySelector('input'))&&codeText(r.oldValue))||groupPotential(r.target)||labelTouches(r.target)||
    (r.attributeName==='for'&&nodes.some(e=>e.id&&e.id===r.oldValue))||
    (r.attributeName==='id'&&nodes.some(e=>(e.getAttribute('aria-labelledby')||'').split(/\s+/).includes(r.oldValue)))||selectorAttribute(r)):
    r.type==='characterData'?((selector!==null&&!simple)||inLabel(r.target)||((sourceRelated(r.target)||r.target.parentElement?.closest('label'))&&(codeText(r.oldValue)||codeText(r.target.data)))):
    groupContainers.has(r.target)||(selector!==null&&!simple)||[...r.addedNodes,...r.removedNodes].some(n=>touches(n)||authority(n)||
      ((sourceRelated(r.target)||(r.target.nodeType===1&&r.target.closest('label')))&&codeText(n.textContent)))||inLabel(r.target);
  let bad=false, closed=false;
  const historyLength=history.length;
  if(!self.navigation)throw Error('unsupported navigation authority');
  const dirty=()=>{bad=true};
  navigation.addEventListener('navigate',dirty);
  addEventListener('popstate',dirty);addEventListener('hashchange',dirty);
  const filled=new Map();
  // Direct name bindings cannot depend on a sibling button's disabled state.
  // Keep original buttons only; never relax selected/ancestor/label objects.
  const directNames=!group&&spec?.layout==='ordered_cells'&&nodes.length===spec.fields.length&&
    nodes.every(n=>n.tagName==='INPUT')&&spec.fields.every(f=>/^input\[name="[A-Za-z_][A-Za-z0-9_-]*"\]$/.test(f.selector));
  const uiButtons=new Map();
  if(directNames){
    const buttons=roots.flatMap(r=>Array.from(r.querySelectorAll('button')));
    if(buttons.length<=200)for(const b of buttons){
      const a=b.getAttribute('disabled');
      if((a===null||a==='')&&!protectedNodes.has(b)&&!inLabel(b)&&!sourceRelated(b))
        uiButtons.set(b,{attribute:a,dataDisabled:b.getAttribute('data-disabled'),attrs:attrs(b),path:path(b)});
    }
  }
  // Reconciliation is metadata acknowledgement, never a fresh destination.
  // Only direct names have proven selector dependencies; metadata-only frame
  // and discovery views retain the same census without acquiring setters.
  const directBinding=s=>/^input\[name="[A-Za-z_][A-Za-z0-9_-]*"\]$/.test(s);
  const reconcileView=reconcileCode&&!group&&selector===null&&(
    spec ? spec.layout==='ordered_cells'&&spec.validation?.charset==='ascii_digits'&&
      spec.fields.every(f=>directBinding(f.selector)) :
      inspection||nodes.every(e=>e.matches('iframe,frame')));
  const numericMetadata=new Map();
  if(reconcileView)for(const e of query('input')){
    if(e.getAttribute('type')!=='text'||e.autocomplete!=='one-time-code'||
      e.inputMode!=='numeric'||!['[0-9]*','[0-9]','[0-9]{1}'].includes(e.pattern)||
      !/^code-?\d+$/.test(e.name)||e.hasAttribute('value')||
      e.hasAttribute('maxlength')||e.matches(':disabled')||e.readOnly||
      inLabel(e)||sourceRelated(e)||Array.from(e.attributes,a=>a.value).some(v=>
        /password|credential|credit|payment|cardnumber|cc-number|username|email|recovery|coupon|promo/i.test(v)))continue;
    numericMetadata.set(e,{name:e.name,attrs:attrs(e),path:path(e),form:e.form,root:e.getRootNode()});
  }
  // Patch precisely one attribute in each frozen representation. In particular,
  // never refresh a complete snapshot from a node with accompanying bad attrs.
  const patchAttribute=(a,key,value)=>{
    const entries=JSON.parse(a),i=entries.findIndex(x=>x[0]===key);
    if(value===null){if(i>=0)entries.splice(i,1)}
    else if(i>=0)entries[i][1]=value;else entries.push([key,value]);
    return JSON.stringify(entries);
  };
  const declaration=value=>{
    // Parse complete states off-document. Reject syntax whose loss/merging by
    // CSSOM would make the historical declaration stream ambiguous.
    const text=String(value||'');
    if(/[\\{}/*]/.test(text))return null;
    const parts=text.split(';').map(x=>x.trim()).filter(Boolean), names=new Set(), expanded=new Set();
    const style=doc.createElement('span').style;
    for(const part of parts){
      const match=/^([a-zA-Z-]+)\s*:\s*(.+)$/.exec(part);if(!match)return null;
      const key=match[1].startsWith('--')?match[1]:match[1].toLowerCase();
      if(names.has(key))return null;names.add(key);
      const single=doc.createElement('span').style;
      single.setProperty(key,match[2].replace(/\s*!important\s*$/i,''),/!important\s*$/i.test(match[2])?'important':'');
      if(!single.getPropertyValue(key)||Array.from(single).some(k=>expanded.has(k)))return null;
      for(const k of single){expanded.add(k);style.setProperty(k,single.getPropertyValue(k),single.getPropertyPriority(k))}
    }
    // Shorthand/longhand overlaps and unsupported declarations are ambiguous.
    if(style.length!==expanded.size)return null;
    return Array.from(style,k=>[k,style.getPropertyValue(k),style.getPropertyPriority(k)]);
  };
  const literalColor=value=>CSS.supports('color',value)&&
    !/^(?:inherit|initial|unset|revert|revert-layer)$/i.test(value.trim())&&
    !/(?:var|env|attr|url)\s*\(/i.test(value);
  const caretState=(value,e,m)=>{
    const state=declaration(value);if(!state||!m.caretColors)return null;
    const caret=state.find(x=>x[0]==='caret-color');if(!caret)return null;
    const color=caret[1].trim(),variable=/^var\(\s*(--[A-Za-z0-9_-]+)\s*\)$/.exec(color);
    if(variable){
      const original=m.caretColors.get(variable[1]);
      if(!original||getComputedStyle(e).getPropertyValue(variable[1])!==original)return null;
    }else if(color!=='auto'&&!literalColor(color))return null;
    return JSON.stringify(state.map(x=>x[0]==='caret-color'?[x[0],'caret',x[2]]:x));
  };
  const patchFrozen=(e,key,value)=>{
    const snap=snapshots.find(s=>s[0]===e);if(snap)snap[1]=patchAttribute(snap[1],key,value);
    const retained=saved.find(s=>s.e===e);if(retained)retained.attrs=patchAttribute(retained.attrs,key,value);
  };
  const paint=new Map();
  const tokens=value=>{
    const t=String(value||'').trim().split(/\s+/).filter(Boolean);
    return t.every(x=>/^[a-zA-Z_][\w-]*$/.test(x))&&new Set(t).size===t.length?t:null;
  };
  const conflict=value=>/password|credential|payment|credit|card|login|username|email|promo|coupon|recovery|secret|token|otp|code|pin/i.test(value);
  const cssWitness=()=>{
    try{
      const sheets=[...doc.styleSheets,...doc.adoptedStyleSheets];
      // Shadow styling needs its own cascade proof; it remains unsupported.
      if(roots.some(r=>r!==doc)||sheets.length>64)return null;
      const rules=[], sheetStates=[], visiting=new Set();
      let textSize=0;
      const walkSheet=(sheet,ancestry,eligible,depth)=>{
        if(depth>12||sheetStates.length>=64||visiting.has(sheet))throw Error();
        visiting.add(sheet);
        const media=sheet.media?.mediaText||'';
        sheetStates.push([sheet,sheet.disabled,media,sheet.ownerNode,sheet.href]);
        walk(sheet.cssRules,ancestry,eligible&&!sheet.disabled&&!media,depth);
        visiting.delete(sheet);
      };
      const walk=(list,ancestry,eligible,depth)=>{
        if(depth>12)throw Error();
        for(const rule of list){
          if(rules.length>=4096)throw Error();
          const text=rule.cssText, selector=rule.selectorText;
          textSize+=text.length;if(textSize>2097152)throw Error();
          const children=rule.cssRules;
          // A group's own prelude must be checked separately from its children.
          const header=children?text.slice(0,text.indexOf('{')):text;
          const layer=rule.constructor?.name==='CSSLayerBlockRule'&&/^@layer\s*(?:[\w.-]+\s*)?\{$/.test(header+'{');
          rules.push([rule,text,selector,eligible,ancestry.slice(),header]);
          if(rule.type===CSSRule.IMPORT_RULE){
            // Read imports even when conditional: an opaque dependency is not
            // evidence of absence. Import references are conservatively ineligible.
            if(!rule.styleSheet)throw Error();
            walkSheet(rule.styleSheet,[...ancestry,rule],false,depth+1);
          }
          if(children)walk(children,[...ancestry,rule],eligible&&layer,depth+1);
        }
      };
      for(const sheet of sheets)walkSheet(sheet,[],true,0);
      return {sheets,rules,sheetStates};
    }catch{return null}
  };
  const sameCSS=w=>{
    const now=cssWitness();return now&&now.sheets.length===w.sheets.length&&
      now.sheets.every((s,i)=>s===w.sheets[i])&&now.rules.length===w.rules.length&&
      now.sheetStates.length===w.sheetStates.length&&
      now.sheetStates.every((s,i)=>s.every((v,j)=>v===w.sheetStates[i][j]))&&
      now.rules.every((r,i)=>r[0]===w.rules[i][0]&&r[1]===w.rules[i][1]&&
        r[3]===w.rules[i][3]&&r[4].length===w.rules[i][4].length&&
        r[4].every((a,j)=>a===w.rules[i][4][j]));
  };
  const geometry=e=>{
    const c=getComputedStyle(e),r=e.getBoundingClientRect();
    if(!e.isConnected||!e.getClientRects().length||c.display==='none'||c.visibility!=='visible'||
      !Number.isFinite(Number(c.opacity))||Number(c.opacity)<=0||Number(c.opacity)>1||
      c.contentVisibility==='hidden'||r.width<=0||r.height<=0)return null;
    return JSON.stringify([r.x,r.y,r.width,r.height,c.display,c.visibility,c.opacity,c.transform,c.clipPath,c.overflow]);
  };
  const boundedShadow=value=>{
    if(value==='none')return true;
    // One ordinary sRGB shadow; bound every resolved length, not variable names.
    const rest=value.replace(/rgba?\([\d.,\s]+\)/g,'').trim().replace(/(?<![\w.])0(?![\w.])/g,'0px');
    if(!/^-?[\d.]+px\s+-?[\d.]+px\s+[\d.]+px\s+-?[\d.]+px$/.test(rest))return false;
    const lengths=rest.split(/\s+/).map(parseFloat);
    return lengths.every(Number.isFinite)&&lengths.every(v=>Math.abs(v)<=4)&&lengths[2]>=0;
  };
  const shadowSafe=e=>boundedShadow(getComputedStyle(e).boxShadow);
  const css= numericMetadata.size?cssWitness():null;
  // A style attribute change must not activate other CSS rules or labels.
  // Consider conditional/group preludes too; opaque syntax fails closed.
  const caretIndependent=!!css&&!css.rules.some(([rule,,selector,,,header])=>{
    const dependency=typeof selector==='string'?selector:header;
    return /\\|\[[^\]]*\bstyle\b/i.test(dependency)||/attr\(\s*style\b/i.test(rule.cssText);
  });
  if(caretIndependent)for(const [e,m] of numericMetadata){
    const computed=getComputedStyle(e),colors=new Map();
    if(computed.length<=8192)for(const key of computed){
      if(!/^--[A-Za-z0-9_-]+$/.test(key))continue;
      const value=computed.getPropertyValue(key);
      if(value.trim()&&literalColor(value))colors.set(key,value);
    }
    m.caretColors=colors;
  }
  const admissibleSpan=(span,e)=>{
    return !(span?.tagName!=='SPAN'||span.getRootNode()!==doc||inLabel(span)||sourceRelated(span)||
      span.closest('label')||span.querySelectorAll('input').length!==1||
      Array.from(span.querySelectorAll('a,button,select,textarea,iframe,frame,object,embed,details,summary,audio,video,label,[contenteditable],[tabindex],[role]')).some(n=>n!==e)||
      Array.from(span.attributes).some(a=>!['class','style'].includes(a.name)&&!a.name.startsWith('data-'))||
      conflict(span.className)||!tokens(span.className)||!geometry(span)||!geometry(e));
  };
  // These facts are used only during this synchronous constructor. Never reuse
  // admission results for validation, where labels and sources are rechecked.
  const originalSpans=new Map();
  if(css)for(const e of numericMetadata.keys()){
    const span=e.parentElement?.closest('span');
    originalSpans.set(e,{span,admissible:admissibleSpan(span,e),tokens:span&&tokens(span.className)});
  }
  if(css)for(const [e,m] of numericMetadata){
    const initial=originalSpans.get(e),span=initial.span;
    if(!initial.admissible)continue;
    const candidates=[];
    for(const [rule,,selectorText,eligible] of css.rules){
      if(!eligible||typeof selectorText!=='string')continue;
      const match=/^\.([a-zA-Z_][\w-]*)$/.exec(selectorText);if(!match||conflict(match[1]))continue;
      const token=match[1],d=rule.style;
      if(rule.cssRules?.length)continue;
      // Authority comes from an original class, or the one originally focused
      // sibling with exactly the same immutable core. Never predict new tokens.
      const core=tokens(span.className).filter(t=>t!==token);
      const anchors=[...numericMetadata.keys()].filter(n=>{
        const candidate=originalSpans.get(n),s=candidate.span,t=candidate.tokens;
        return s&&t&&candidate.admissible&&t.includes(token)&&(s===span||
          (doc.activeElement===n&&
           (s.parentNode===span.parentNode||(n.form!==null&&n.form===e.form))&&core.length>0&&
           t.filter(x=>x!==token).join(' ')===core.join(' ')));
      });
      if(!anchors.length)continue;
      const declared=d.cssText.split(';').map(x=>x.trim()).filter(Boolean).map(x=>x.split(':')[0].trim());
      if(declared.length!==2||!declared.includes('border-color')||!declared.includes('box-shadow')||
        declared.some(k=>d.getPropertyPriority(k)))continue;
      // Any other reference, including class-attribute selectors, could alter
      // descendants or layout. No selector inference from today's DOM.
      if(css.rules.some(([r,,sel,,,header])=>{
        if(r===rule)return false;
        const dependency=typeof sel==='string'?sel:header;
        // Escapes and generic class attributes cannot prove token independence.
        // Unrelated pseudo selectors are harmless to this token-specific proof.
        return dependency.includes(token)||/\\|\[\s*(?:[\w*-]+\|)?class\b/i.test(dependency)||
          /attr\(\s*class\b/i.test(r.cssText);
      }))continue;
      const vars=[...rule.cssText.matchAll(/var\(\s*(--[\w-]+)\s*\)/g)].map(x=>x[1]);
      const stripped=rule.cssText.replace(/var\(\s*--[\w-]+\s*\)/g,'0');
      if(/var\(|env\(|attr\(|url\(/i.test(stripped))continue;
      const values=vars.map(v=>[v,getComputedStyle(span).getPropertyValue(v)]);
      // Dependencies must resolve to plain colors/lengths, never further CSS
      // dependencies, animations or fallback branches.
      if(values.some(([,v])=>!v.trim()||/[();{}]/.test(v)&&!/^\s*rgba?\([\d.,\s]+\)\s*$/.test(v)))continue;
      const resolved=value=>value.replace(/var\(\s*(--[\w-]+)\s*\)/g,(_,key)=>values.find(x=>x[0]===key)?.[1]||'');
      const shadow=resolved(d.getPropertyValue('box-shadow'));
      // Validate the inactive rule too: add/remove within one batch cannot
      // conceal an oversized transient shadow.
      const parser=doc.createElement('span').style;
      parser.boxShadow=shadow;
      if(!parser.boxShadow||!boundedShadow(parser.boxShadow)||
        !CSS.supports('border-color',resolved(d.getPropertyValue('border-color'))))continue;
      candidates.push({token,rule,values,anchors:anchors.map(n=>{
        const s=n.parentElement.closest('span');
        return {e:n,span:s,path:path(s),core:tokens(s.className).filter(t=>t!==token),
          attrs:patchAttribute(attrs(s),'class',null)};
      })});
    }
    // A single original rule is necessary; runtime class changes choose none.
    if(candidates.length!==1)continue;
    const witness=candidates[0],core=tokens(span.className).filter(t=>t!==witness.token);
    const linked=(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>doc.getElementById(id));
    if(linked.some(n=>!n))continue;
    const related=[...path(e).slice(0,path(e).indexOf(span)+1),...Array.from(e.labels||[]),...linked];
    if(related.some(n=>!geometry(n))||!shadowSafe(span))continue;
    paint.set(span,{...witness,core,css,attrs:attrs(span),path:path(span),e,
      geometry:related.map(n=>[n,geometry(n)])});
  }
  const paintValid=(span,w,cssOK)=>
    (cssOK===undefined?sameCSS(w.css):cssOK)&&span.isConnected&&
    path(span).length===w.path.length&&path(span).every((n,i)=>n===w.path[i])&&
    span.contains(w.e)&&span.querySelectorAll('input').length===1&&
    !sourceRelated(span)&&!inLabel(span)&&
    w.anchors.every(a=>a.span.isConnected&&a.span.contains(a.e)&&
      path(a.span).length===a.path.length&&path(a.span).every((n,i)=>n===a.path[i])&&
      patchAttribute(attrs(a.span),'class',null)===a.attrs&&
      tokens(a.span.className)?.filter(t=>t!==w.token).join(' ')===a.core.join(' '))&&
    w.values.every(([v,value])=>getComputedStyle(span).getPropertyValue(v)===value)&&
    w.geometry.every(([n,g])=>geometry(n)===g)&&shadowSafe(span);
  const reconcile=records=>{
    const accepted=new Set();
    let caretCSSOK;
    for(const [e,m] of numericMetadata){
      const own=records.filter(r=>r.type==='attributes'&&r.target===e);
      const bookkeeping=own.filter(r=>r.attributeName==='name'||r.attributeName==='type');
      // Every observer delivery must contain a full transaction. A partial or
      // reverted conflicting transaction reaches the ordinary sticky refusal.
      if(bookkeeping.length&&bookkeeping.length%3===0){
        let exact=true;
        for(let i=0;i<bookkeeping.length;i+=3){
          const [a,b,c]=bookkeeping.slice(i,i+3);
          if(a.attributeName!=='name'||a.oldValue!==m.name||
            b.attributeName!=='type'||b.oldValue!=='text'||
            c.attributeName!=='name'||c.oldValue!=='')exact=false;
        }
        if(exact&&e.getAttribute('name')===m.name&&e.getAttribute('type')==='text')
          for(const r of bookkeeping)accepted.add(r);
      }
      const styles=own.filter(r=>r.attributeName==='style');
      if(styles.length){
        const before=JSON.parse(m.attrs).find(a=>a[0]==='style')?.[1]??null;
        if(caretCSSOK===undefined)caretCSSOK=caretIndependent&&sameCSS(css);
        if(caretCSSOK&&styles[0].oldValue===before&&
          caretState(before,e,m)!==null&&styles.every(r=>caretState(r.oldValue,e,m)===caretState(before,e,m))&&
          caretState(e.getAttribute('style'),e,m)===caretState(before,e,m)){
          for(const r of styles)accepted.add(r);
          const value=e.getAttribute('style');
          m.attrs=patchAttribute(m.attrs,'style',value);
          patchFrozen(e,'style',value);
        }
      }
    }
    for(const [span,w] of paint){
      const changes=records.filter(r=>r.type==='attributes'&&r.target===span&&r.attributeName==='class');
      if(!changes.length)continue;
      const original=JSON.parse(w.attrs).find(a=>a[0]==='class')?.[1]??null;
      const states=[...changes.map(r=>r.oldValue),span.getAttribute('class')];
      const allowed=value=>{const t=tokens(value);return t&&
        t.filter(x=>x!==w.token).join(' ')===w.core.join(' ')};
      // Only the one proven paint token may toggle. Other attribute histories
      // remain in the original guard, including reverted style/role changes.
      if(states[0]!==original||!states.every(allowed)||!paintValid(span,w))continue;
      for(const r of changes)accepted.add(r);
      w.attrs=patchAttribute(w.attrs,'class',span.getAttribute('class'));
      patchFrozen(span,'class',span.getAttribute('class'));
    }
    // Unsupported class changes on an OTP ancestor must refuse even in
    // metadata-only views where that ancestor isn't a protected setter path.
    if(records.some(r=>r.type==='attributes'&&r.attributeName==='class'&&
      [...numericMetadata.keys()].some(e=>path(e).includes(r.target))&&!accepted.has(r)))bad=true;
    return records.filter(r=>!accepted.has(r));
  };
  const cssOwners=new Set(css?css.sheetStates.map(s=>s[3]).filter(Boolean):[]);
  const styleElement=n=>n?.nodeType===1&&['style','link'].includes(n.localName);
  const carriesStyle=n=>n?.nodeType===1&&(styleElement(n)||!!n.querySelector('style,link'));
  const stylesheetMutation=r=>styleElement(r.target)||[...cssOwners].some(n=>n.contains(r.target))||
    (r.type==='childList'&&[...r.addedNodes,...r.removedNodes].some(carriesStyle));
  // Head title text is presentation, not an OTP receiver. Retain its exact
  // original identity and nonempty single-text topology so even :empty CSS
  // dependencies cannot change. Attribute/source/structural histories refuse.
  const titleHead=doc.head;
  const titleElements=titleHead?Array.from(titleHead.children).filter(e=>
    e.namespaceURI==='http://www.w3.org/1999/xhtml'&&e.localName==='title'):[];
  const quietTitle=titleElements.length===1&&titleElements[0].attributes.length===0?
    titleElements[0]:null;
  const titleText=n=>n?.nodeType===3&&n.length>0&&n.length<=512;
  let titleNode=quietTitle?.childNodes.length===1&&titleText(quietTitle.firstChild)?quietTitle.firstChild:null;
  const withoutTitleText=records=>{
    if(!titleNode||!quietTitle.isConnected||doc.head!==titleHead||quietTitle.parentNode!==titleHead||
      quietTitle.attributes.length||quietTitle.childNodes.length!==1||!titleText(quietTitle.firstChild)||
      protectedNodes.has(quietTitle)||sourceRelated(quietTitle)||inLabel(quietTitle)||
      Array.from(titleHead.children).filter(e=>e.namespaceURI==='http://www.w3.org/1999/xhtml'&&e.localName==='title').length!==1)return records;
    const nodes=new Set([titleNode]);
    for(const r of records)if(r.type==='childList'&&r.target===quietTitle)
      for(const n of [...r.addedNodes,...r.removedNodes])nodes.add(n);
    const related=records.filter(r=>r.target===quietTitle||(r.type==='characterData'&&nodes.has(r.target)));
    if(!related.length)return records;
    if(getComputedStyle(titleHead).display!=='none'||getComputedStyle(quietTitle).display!=='none'||
      path(quietTitle).some(n=>n.nodeType===1&&n.getAttribute('dir')?.trim().toLowerCase()==='auto'))return records;
    let cursor=titleNode;
    for(const r of related){
      if(r.type==='characterData'){
        if(r.target!==cursor||typeof r.oldValue!=='string'||r.oldValue.length===0||
          r.oldValue.length>512||!titleText(r.target))return records;
      }else if(r.type==='childList'&&r.addedNodes.length===1&&r.removedNodes.length===1&&
        r.removedNodes[0]===cursor&&titleText(cursor)&&titleText(r.addedNodes[0])&&
        r.previousSibling===null&&r.nextSibling===null)cursor=r.addedNodes[0];
      else return records;
    }
    if(cursor!==quietTitle.firstChild)return records;
    titleNode=cursor;
    return records.filter(r=>!related.includes(r));
  };
  const learnHistory=records=>{
    collectSources();
    // Detached subtree links still resolve in the mutation's observed root.
    // Learn every nested dependency before evaluating any historical record.
    for(const r of records)if(r.type==='childList'){
      const root=linkRoots.get(r.target)||r.target.getRootNode();if(!sourceIds.has(root))sourceIds.set(root,new Set());
      for(const n of [...r.addedNodes,...r.removedNodes])if(n.nodeType===1){
        for(const e of [n,...n.querySelectorAll('*')]){
          linkRoots.set(e,root);
          for(const id of (e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean))sourceIds.get(root).add(id);
        }
      }
    }
    // Learn the whole batch's historical links before evaluating earlier records.
    for(const r of records)if(r.type==='attributes'&&r.attributeName==='aria-labelledby'){
      const root=linkRoots.get(r.target)||r.target.getRootNode();if(!sourceIds.has(root))sourceIds.set(root,new Set());
      for(const id of [r.oldValue,r.target.getAttribute('aria-labelledby')].flatMap(v=>String(v||'').split(/\s+/).filter(Boolean)))sourceIds.get(root).add(id);
    }
    for(const [root,ids] of sourceIds)for(const id of ids){const source=root.getElementById(id);if(source)sources.add(source);}
    for(const r of records)if(r.type==='attributes'&&r.attributeName==='id'){
      const ids=sourceIds.get(r.target.getRootNode());
      if(ids&&[r.oldValue,r.target.id].some(id=>id&&ids.has(id)))sources.add(r.target);
    }
  };
  const mutationsBad=records=>{
    learnHistory(records);
    records=withoutTitleText(records);
    if(caretIndependent&&records.some(stylesheetMutation))bad=true;
    if(paint.size&&records.some(r=>r.type==='characterData'||r.type==='childList'||
      (r.type==='attributes'&&[...paint.values()].some(w=>w.path.includes(r.target))&&r.attributeName!=='class')))bad=true;
    records=reconcile(records);
    if(spec&&records.some(r=>r.type==='childList'||r.type==='characterData'||(r.type==='attributes'&&!protectedNodes.has(r.target))))return true;
    return records.some(relevant);
  };
  const observer=new MutationObserver(r=>{if(mutationsBad(r))bad=true});
  const observe=root=>observer.observe(root,{subtree:true,childList:true,attributes:true,attributeOldValue:true,characterData:true,characterDataOldValue:true});
  for(const root of roots)observe(root);
  const focused=e=>{let active=doc.activeElement;for(const root of roots)if(root instanceof ShadowRoot&&root.host===active&&root.activeElement)active=root.activeElement;return active===e};
  const valid=()=>{
    if(mutationsBad(observer.takeRecords()))bad=true;
    if(snapshots.some(([n,a])=>attrs(n)!==a))bad=true;
    const currentCSS=(paint.size||caretIndependent)?sameCSS(css):null;
    if(caretIndependent&&!currentCSS)bad=true;
    for(const [span,w] of paint)if(attrs(span)!==w.attrs||!paintValid(span,w,currentCSS))bad=true;
    for(const [e,m] of numericMetadata)if(!e.isConnected||e.ownerDocument!==doc||
      e.getRootNode()!==m.root||e.form!==m.form||attrs(e)!==m.attrs||
      path(e).length!==m.path.length||path(e).some((n,i)=>n!==m.path[i]))bad=true;
    if(selector!==null&&!inspection){const matches=roots.filter(r=>r===doc||r.host.isConnected).flatMap(r=>Array.from(r.querySelectorAll(selector)));
      if(matches.length!==selected.length||matches.some((e,i)=>e!==selected[i]))bad=true;}
    if(spec&&bindings.some((s,i)=>{const matches=query(s);return matches.length!==bound[i].length||matches.some((e,j)=>e!==bound[i][j]);}))bad=true;
    if(container){const current=Array.from(container.querySelectorAll(spec.field_selector));if(current.length!==members.length||current.some((e,i)=>e!==members[i]))bad=true;}
    if(Array.from(filled).some(([i,v])=>read(saved[i].e)!==v))bad=true;
    if(group?.canonical&&filled.size&&group.canonical.value!==nodes.map(n=>n.value).join(''))bad=true;
    return !bad&&!closed&&document===doc&&self.origin===origin&&location.href===href&&history.length===historyLength&&
      saved.every(s=>s.e.isConnected&&s.e.ownerDocument===doc&&attrs(s.e)===s.attrs&&
        path(s.e).length===s.path.length&&path(s.e).every((n,i)=>n===s.path[i])&&
        form(s.e)===s.form&&(!s.form||(s.form.isConnected&&attrs(s.form)===s.formAttrs&&s.form.action===s.action&&s.form.method===s.method))&&
        (inspection||((completed||!s.e.matches(':disabled'))&&!s.e.readOnly&&
        (!s.e.matches('[contenteditable]')||(s.e.isContentEditable&&!(s.e.parentElement||s.e.getRootNode().host)?.isContentEditable&&
          !s.e.children.length&&Array.from(s.e.childNodes).every(n=>n.nodeType===3)))&&
        !path(s.e).some(n=>n.nodeType===1&&n.hasAttribute('inert'))&&s.e.getClientRects().length&&
        getComputedStyle(s.e).display!=='none'&&getComputedStyle(s.e).visibility==='visible')));
  };
  let lastChecks=null;
  return Object.freeze({document:doc,valid,
    lastWriteChecks(){return lastChecks},
    accepts(value){return valid()&&(!group||(value.length===nodes.length&&(!group.numeric||/^[0-9]+$/.test(value))))},
    censusRoot(root){if(!roots.includes(root)){roots.push(root);observe(root);if(spec)bad=true;
      if(Array.from(root.querySelectorAll('*')).some(n=>semantic(n)||groupPotential(n)))bad=true;}return valid()},
    censusNode(n){if(authority(n))bad=true;return valid()},
    close(){closed=true;lastChecks=null;observer.disconnect();navigation.removeEventListener('navigate',dirty);
    removeEventListener('popstate',dirty);removeEventListener('hashchange',dirty);filled.clear();uiButtons.clear();numericMetadata.clear();paint.clear();originalSpans.clear();cssOwners.clear();selected.length=0;saved.length=0;nodes.length=0;roots.length=0;protectedNodes.clear();labels.clear();sources.clear();sourceIds.clear();snapshots.length=0},
    focus(i){if(!valid())return false;saved[i].e.focus();return valid()&&doc.hasFocus()&&focused(saved[i].e)},
    write(i,value){if(!valid()||!doc.hasFocus()||!focused(saved[i].e))return {written:false,valid:false};
      const e=saved[i].e, previousCanonical=group?.canonical?.value;
      const previousValueAttribute=e.getAttribute('value');
      const finalNumeric = !!group?.numeric && i === saved.length - 1 && filled.size === saved.length - 1;
      if(e.tagName==='INPUT'||e.tagName==='TEXTAREA'){
        const proto=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(proto,'value').set.call(e,value);
      }else if(spec&&['plaintext-only','true'].includes(e.getAttribute('contenteditable'))&&e.isContentEditable&&
        !(e.parentElement||e.getRootNode().host)?.isContentEditable&&!e.children.length){
        const before=Array.from(e.childNodes);
        Object.getOwnPropertyDescriptor(Node.prototype,'textContent').set.call(e,value);
        const records=observer.takeRecords();
        if(records.length!==1||records.some(r=>r.type!=='childList'||r.target!==e||
          r.removedNodes.length!==before.length||Array.from(r.removedNodes).some((n,j)=>n!==before[j]||n.nodeType!==3)||
          r.addedNodes.length!==1||r.addedNodes[0]!==e.firstChild||e.childNodes.length!==1||
          r.addedNodes[0].nodeType!==3||r.addedNodes[0].textContent!==value))bad=true;
        // Fixed text selection, never HTML or an editor-specific callback.
        const range=doc.createRange();range.selectNodeContents(e);range.collapse(false);
        const selection=doc.getSelection();selection.removeAllRanges();selection.addRange(range);
      }else return {written:false,valid:false};
      filled.set(i,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));
      let explicitRecords=null;
      if(!group&&spec&&spec.layout!=='single'&&spec.validation.charset==='ascii_digits'&&
          e.matches('input[type="text"],input[type="tel"],input[type="number"]')){
        // Controlled explicit cells need no legacy maxlength/group heuristic.
        // Acknowledge only this setter's single exact value reflection; all
        // other records and complete retained snapshots remain authoritative.
        const records=observer.takeRecords();
        const values=records.filter(r=>r.type==='attributes'&&r.target===e&&r.attributeName==='value');
        const own=values.length===1&&values[0].oldValue===previousValueAttribute&&
          e.getAttribute('value')===value&&read(e)===value;
        if(own)patchFrozen(e,'value',value);
        explicitRecords=records.filter(r=>!own||r!==values[0]);
      }
      if(uiButtons.size){
        const records=explicitRecords||observer.takeRecords();
        // Learn the whole history before acknowledging even unchanged metadata.
        learnHistory(records);
        const buttonRecords=records.filter(r=>r.type==='attributes'&&
          ['disabled','data-disabled'].includes(r.attributeName));
        const noops=new Set();
        if(buttonRecords.length&&new Set(buttonRecords.map(r=>r.target)).size===1){
          const b=buttonRecords[0].target,s=uiButtons.get(b);
          const disabledRecords=buttonRecords.filter(r=>r.attributeName==='disabled');
          const dataRecords=buttonRecords.filter(r=>r.attributeName==='data-disabled');
          const mirror=v=>v===null||v==='false'?false:v===''||v==='true'?true:undefined;
          const strip=v=>patchAttribute(patchAttribute(v,'disabled',null),'data-disabled',null);
          if(s&&[null,'','true','false'].includes(s.dataDisabled)&&
            b.isConnected&&b.ownerDocument===doc&&!protectedNodes.has(b)&&!inLabel(b)&&!sourceRelated(b)&&
            path(b).length===s.path.length&&path(b).every((n,j)=>n===s.path[j])&&
            strip(attrs(b))===strip(s.attrs)&&disabledRecords.length<=1&&dataRecords.length<=1&&
            buttonRecords.every(r=>r.oldValue===(r.attributeName==='disabled'?s.attribute:s.dataDisabled))){
            const a=b.getAttribute('disabled'),d=b.getAttribute('data-disabled');
            const unchanged=a===s.attribute&&d===s.dataDisabled;
            // A mirrored flag may change only alongside the already-supported
            // single native disabled transition, with coherent before/after states.
            const paired=disabledRecords.length===1&&dataRecords.length===1&&
              (a===null||a==='')&&a!==s.attribute&&
              mirror(s.dataDisabled)===(s.attribute!==null)&&mirror(d)===(a!==null);
            if(unchanged||paired)for(const r of buttonRecords)noops.add(r);
          }
        }
        const allowed=r=>{
          if(noops.has(r))return true;
          if(r.type!=='attributes'||r.attributeName!=='disabled')return false;
          const b=r.target,s=uiButtons.get(b),a=b.getAttribute('disabled');
          return !!s&&(a===null||a==='')&&a!==s.attribute&&r.oldValue===s.attribute&&
            records.filter(x=>x.type==='attributes'&&x.attributeName==='disabled').length===1&&
            b.isConnected&&b.ownerDocument===doc&&!protectedNodes.has(b)&&!inLabel(b)&&!sourceRelated(b)&&
            path(b).length===s.path.length&&path(b).every((n,j)=>n===s.path[j]);
        };
        const accepted=records.filter(allowed);
        if(mutationsBad(records.filter(r=>!accepted.includes(r))))bad=true;
        for(const r of accepted){
          const s=uiButtons.get(r.target),value=r.target.getAttribute(r.attributeName);
          if(r.attributeName==='disabled')s.attribute=value;
          else if(r.attributeName==='data-disabled')s.dataDisabled=value;
          s.attrs=patchAttribute(s.attrs,r.attributeName,value);
        }
      }else if(explicitRecords&&mutationsBad(explicitRecords))bad=true;
      if(group){
        const final=i===saved.length-1&&filled.size===saved.length;
        const records=observer.takeRecords();
        const token=v=>String(v||'').split(/\s+/).filter(Boolean);
        const expectedClass=r=>{
          if(r.target!==e||r.attributeName!=='class')return false;
          const before=token(r.oldValue),after=token(e.className);
          return after.includes('filled')&&!after.includes('error')&&
            before.filter(t=>!['filled','error'].includes(t)).join(' ')===after.filter(t=>!['filled','error'].includes(t)).join(' ');
        };
        const ownValueRecords=records.filter(r=>r.type==='attributes'&&r.target===e&&r.attributeName==='value');
        const ownValue = group.numeric && ownValueRecords.length === 1 &&
          ownValueRecords[0].oldValue === previousValueAttribute &&
          e.getAttribute('value') === value && e.value === value;
        const allowed=r=>r.type==='attributes'&&(expectedClass(r)||
          (ownValue && r === ownValueRecords[0])||
          (r.target===group.canonical&&r.attributeName==='min'&&r.oldValue===String(saved.length)&&r.target.getAttribute('min')===r.oldValue)||
          (r.target===group.canonical&&r.attributeName==='value'&&r.target.type==='hidden'&&
            r.target.getAttribute('value')===nodes.map(n=>n.value).join('')&&
            (r.oldValue===previousCanonical||r.oldValue===r.target.value||(r.oldValue===null&&previousCanonical==='')))||
          (final&&nodes.includes(r.target)&&r.attributeName==='disabled'&&r.oldValue===null&&r.target.disabled));
        if(mutationsBad(records.filter(r=>!allowed(r))))bad=true;
        completed=final&&nodes.every(n=>n.disabled);
        for(const r of records.filter(allowed)){
          const snapshot=snapshots.find(s=>s[0]===r.target);if(snapshot)snapshot[1]=attrs(r.target);
          const s=saved.find(s=>s.e===r.target);if(s)s.attrs=attrs(s.e);
        }
        if(group.canonical&&group.canonical.value!==nodes.map(n=>n.value).join(''))bad=true;
      }
      // A fully populated numeric group may blur its final retained cell as
      // part of synchronous verification; earlier focus exits still refuse.
      const finalBlur = finalNumeric && filled.size === saved.length && doc.activeElement === doc.body;
      const expectedFocus=(group||(spec&&spec.layout!=='single'))?(finalBlur||completed||focused(saved[Math.min(i+1,saved.length-1)].e)||focused(e)):focused(e);
      const guardOK=valid(),documentFocus=doc.hasFocus();
      lastChecks={guard:guardOK,documentFocus,targetFocus:expectedFocus===true};
      return {written:true,valid:guardOK&&documentFocus&&expectedFocus};}
  });
}'''.replace('__GROUP__', GROUP_JS)


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
        self.censuses = {}
        self.contexts = {}
        self.census_documents = {}
        self.scopes = []
        self.lock = threading.Lock()
        self.closed = False
        self.parent_session = None

    def keep(self, sid, obj):
        self.objects.append((sid, obj))
        return obj

    def discard(self, sid, obj):
        if obj in self.census_documents.values():
            # Retained HTMLDocument references are reads, NOT guard objects.
            # Never invoke their native document.close() while retiring a lease.
            try:
                _call(self.sup, 'Runtime.releaseObject', {'objectId': obj}, sid)
            except Exception:
                pass
            if (sid, obj) in self.objects:
                self.objects.remove((sid, obj))
            return
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


def _document_capacity(sup, sid, context=None, doc=None, *, release=True, tree=None):
    if doc is None and tree is None:
        doc = _eval(sup, sid, context, 'document')['objectId']
    try:
        # Enumerate shadow *headers* even when not piercing. Fetch each custom
        # root explicitly; UA internals and iframe content documents were never
        # this document's controls, so do not serialize their whole trees.
        root = tree if tree is not None else _call(sup, 'DOM.describeNode', {'objectId': doc, 'depth': 128, 'pierce': False}, sid)['result']['node']
        pending, count, shadows, controls = [(root, 0)], 0, [], []
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > 10000:
                raise ValueError('unsupported document capacity')
            if node.get('nodeName', '').upper() in {'INPUT', 'SELECT', 'TEXTAREA', 'IFRAME', 'FRAME'} or 'contenteditable' in node.get('attributes', [])[::2]:
                controls.append(node['backendNodeId'])
                if len(controls) > 200:
                    raise ValueError('control capacity')
            custom = [s for s in node.get('shadowRoots', []) if s.get('shadowRootType') != 'user-agent']
            shadows.extend(s['backendNodeId'] for s in custom)
            if len(shadows) > 128:
                raise ValueError('unsupported document capacity')
            for shadow in custom:
                if depth >= 128:
                    raise ValueError('unsupported document depth')
                subtree = _call(sup, 'DOM.describeNode', {'backendNodeId': shadow['backendNodeId'],
                    'depth': 128 - depth - 1, 'pierce': False}, sid)['result']['node']
                pending.append((subtree, depth + 1))
            children = node.get('children', [])
            if node.get('childNodeCount', 0) > len(children):
                raise ValueError('unsupported document depth')
            pending.extend((child, depth + 1) for child in children)
        return tuple(shadows), tuple(sorted(controls))
    finally:
        if release and doc is not None:
            _call(sup, 'Runtime.releaseObject', {'objectId': doc}, sid)


def _inspection_js(nonce, selector, generic=False):
    from .exact_code import EXPORT_JS
    # Legacy classifier indices exclude textarea/editing hosts, as before.
    controls = 'input,select,textarea,[contenteditable]' if generic else 'input,select'
    return 'function(){const roots=this.slice();const exported=(' + EXPORT_JS + ')(roots,' + json.dumps(controls) + ');const {nodes,rows}=exported;const selector=' + json.dumps(selector) + r''';
      const matches=selector===null?[]:roots.flatMap(r=>Array.from(r.querySelectorAll(selector)));
      for(const row of rows){
        const e=nodes[row.index];row.selected=matches.includes(e)&&!e.matches(':disabled')&&!e.closest('[inert]')&&
          e.getAttribute('aria-disabled')!=='true'&&e.getAttribute('aria-readonly')!=='true';
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


def discover(origin, label, task, parent, field_selector=None, *, top_only=False, target_spec=None):
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

    def visit(sid, frame, ancestry, depth, scope_ancestry=()):
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
                _inspection_js(nonce, field_selector, generic=target_spec is not None), (), False)['objectId'])
            raw = _invoke(sup, sid, inspector, 'function(){return this.raw}').get('value')
            if not isinstance(raw, str) or len(raw) > 100000:
                raise ValueError('inspection capacity')
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > 200:
                raise ValueError('control capacity')
            if field_selector is not None or target_spec is not None:
                selector_matches.append(_invoke(sup, sid, inspector, 'function(){return this.matchCount}').get('value'))
                scope = lease.keep(sid, _invoke(sup, sid, inspector,
                    'function(spec){if(!this.guard.valid())throw Error();return (' + _GUARD + ')([],false,this.roots.slice(),this.selector,spec,true)}', (target_spec,), False)['objectId'])
                lease.censuses[scope] = (shadows, census)
                lease.contexts[scope] = context
                lease.scopes.append((sid, scope, scope_ancestry))
            groups = {}
            root_indices = {r['index']: r['rootIndex'] for r in rows}
            rows_by_index = {r['index']: r for r in rows}
            selected_groups = set()
            if target_spec is not None:
                from .exact_code import RESOLVE_JS
                from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl
                resolved = _invoke(sup, sid, inspector, RESOLVE_JS, (target_spec,)).get('value')
                classified = [] if resolved is None else [ClassifiedLoginControl(LoginControl.from_dict(r), 100, 'one-time-code') for r in resolved['rows']]
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
            if target_spec is not None and classified:
                lease.scopes = [entry for entry in lease.scopes if entry[1] != scope]
                lease.discard(sid, scope)
            for c in classified:
                groups.setdefault(('exact',) if target_spec is not None else (root_indices[c.control.index], c.control.form_index), []).append(c)
            for controls in groups.values():
                if target_spec is None:
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
                lease.censuses[guard] = (shadows, census)
                lease.contexts[guard] = context
                if field_selector is not None and selected_groups:
                    # The retained group guard also owns this document's hint
                    # census. A second empty guard cannot authenticate the same
                    # setter's exact React value-reflection mutations.
                    lease.scopes = [(s, guard if s == sid and g == scope else g, a)
                                    for s, g, a in lease.scopes]
                href = _invoke(sup, sid, inspector, 'function(){return this.href}').get('value')
                targets.append(NestedCodeTarget(origin, label, task, parent, nonce, href,
                    tuple(controls), sup, parent, frame, psid, sid, guard, ancestry, lease,
                    time.monotonic() + 240, field_selector=field_selector, target_spec=target_spec, explicit_parent=not top_only))
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
                'function(){if(this.hasAttribute("sandbox")&&!this.sandbox.contains("allow-same-origin"))throw Error();return (' + _GUARD + ')([this],false,[document,this.getRootNode()].filter((r,i,a)=>a.indexOf(r)===i),null,null,' + json.dumps(target_spec is not None) + ')}', (), False)['objectId'])
            lease.censuses[guard] = (shadows, census)
            lease.contexts[guard] = context
            next_scope_ancestry = ()
            if field_selector is not None or target_spec is not None:
                # A refusal-only canary is not a write destination. Retain its
                # identity/history fences even when a service frame is hidden.
                # Actual selected ancestors keep the strict guard above.
                canary = lease.keep(sid, _invoke(sup, sid, owner_obj,
                    'function(){return (' + _GUARD + ')([this],true,[document,this.getRootNode()].filter((r,i,a)=>a.indexOf(r)===i),null,null,' + json.dumps(target_spec is not None) + ')}', (), False)['objectId'])
                lease.censuses[canary] = (shadows, census)
                lease.contexts[canary] = context
                next_scope_ancestry = scope_ancestry + ((sid, frame, child, owner, canary),)
            visit(sid, child, ancestry + ((sid, frame, child, owner, guard),), depth + 1, next_scope_ancestry)

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
        scope_objects = {(sid, guard) for sid, guard, _ in lease.scopes}
        scope_objects |= {(a[0], a[4]) for _, _, ancestors in lease.scopes for a in ancestors}
        scope_sessions = {sid for sid, _ in scope_objects}
        for target in targets:
            assert_target(target)
            lease.resources[target.leaf_guard] = (
                {(target.leaf_sid, target.leaf_guard)} | {(a[0], a[4]) for a in target.ancestry} | scope_objects |
                {(sid, obj) for (sid, _), obj in lease.census_documents.items()},
                {target.parent_sid, target.leaf_sid} | {a[0] for a in target.ancestry} | scope_sessions)
        lease.prune()  # Inspection/temporary node arrays are no longer authorities.
        if not targets:
            lease.close()
        return targets
    except BaseException:
        lease.close()
        raise


def _check_census(target, sid, guard, current=None):
    """Complete bounded census; differential checks never replace retained targets."""
    sup, lease = target.supervisor, target.lease
    if current is None:
        key = (sid, lease.contexts[guard])
        if key not in lease.census_documents:
            lease.census_documents[key] = lease.keep(sid, _invoke(
                sup, sid, guard, 'function(){return this.document}', (), False)['objectId'])
        current = _document_capacity(sup, sid, doc=lease.census_documents[key], release=False)
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
    return current


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
    ancestors += [a for _, _, path in target.lease.scopes for a in path]
    for sid, frame, child, owner, guard in ancestors:
        if (sid, guard) in checked:
            continue
        checked.add((sid, guard))
        owners.append((len(requests), owner))
        requests.append(('DOM.getFrameOwner', {'frameId': child}, sid))
        guards.append((sid, guard))
    for sid, guard, _ in target.lease.scopes:
        if (sid, guard) not in checked:
            checked.add((sid, guard))
            guards.append((sid, guard))
    if (target.leaf_sid, target.leaf_guard) not in checked:
        guards.append((target.leaf_sid, target.leaf_guard))
    # One complete CDP tree census per exact isolated document at EACH barrier,
    # not one identical traversal per retained guard. All guards still validate
    # and independently consume every differential node/root; no cross-barrier
    # cache, selector re-resolution or setter retargeting is introduced.
    documents = {}
    for sid, guard in guards:
        key = (sid, target.lease.contexts[guard])
        documents.setdefault(key, []).append(guard)
    document_reads = []
    for (sid, context), objects in documents.items():
        key = (sid, context)
        if key not in target.lease.census_documents:
            target.lease.census_documents[key] = target.lease.keep(sid, _invoke(
                sup, sid, objects[0], 'function(){return this.document}', (), False)['objectId'])
        index = len(requests)
        document_reads.append((sid, objects, index))
        requests.append(('Runtime.callFunctionOn', {
            'objectId': objects[0], 'functionDeclaration': GUARD_VALIDATION,
            'arguments': [{'objectId': obj} for obj in objects[1:]],
            'returnByValue': True}, sid))
        requests.append(('DOM.describeNode', {'objectId': target.lease.census_documents[key],
            'depth': 128, 'pierce': False}, sid))
    # Parallelize only within an ordered proof phase. In particular, every
    # guard verdict completes before any document census begins: an unknown
    # shadow root must not be hidden by an earlier stale census reply.
    try:
        replies = [None] * len(requests)
        for method in ('DOM.getFrameOwner', 'Runtime.callFunctionOn', 'DOM.describeNode'):
            indexes = [i for i, request in enumerate(requests) if request[0] == method]
            phase = sup.read_batch([requests[i] for i in indexes])
            for i, reply in zip(indexes, phase):
                replies[i] = reply
    except RuntimeError as exc:
        # Match _invoke's original destroyed-world refusal contract. This never
        # retries, resolves a new context or consumes an unknown write receipt.
        if 'Cannot find context with specified id' not in str(exc):
            raise
        raise ValueError('nested context refused') from None
    for index, owner in owners:
        if replies[index].get('result', {}).get('backendNodeId') != owner:
            raise ValueError('frame owner changed')
    for sid, objects, index in document_reads:
        if _result(replies[index]).get('value') is not True:
            raise ValueError('code document changed')
        response = replies[index + 1]
        if 'error' in response:
            raise ValueError('code document changed')
        current = _document_capacity(sup, sid, release=False, tree=response['result']['node'])
        for guard in objects:
            _check_census(target, sid, guard, current)


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
            if _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                    'function(v){return this.accepts(v)}', (code,)).get('value') is not True:
                raise ValueError('invalid code fields')
            fills = build_otp_fills(list(target.controls), code)
        if not fills or len(fills) != len(target.controls):
            raise ValueError('invalid code fields')
        maximum = target.controls[0].control.max_length
        if len(fills) == 1 and maximum is not None and maximum < len(code):
            raise ValueError('code too long')
        if not target.explicit_parent:
            # Historical top-level fill emulation is not a discovery side effect.
            _call(target.supervisor, 'Emulation.setFocusEmulationEnabled', {'enabled': True}, target.leaf_sid)
        from .bound_cdp import fill_diagnostic
        fill_diagnostic('revalidate', 'guard_refused')
        for i, f in enumerate(fills):
            if time.monotonic() >= expires_at:
                fill_diagnostic(reason='expired')
                return False
            assert_target(target)
            fill_diagnostic('focus', 'focus_refused')
            if _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                    'function(i){return this.focus(i)}', (i,)).get('value') is not True:
                return False
            fill_diagnostic('revalidate', 'guard_refused')
            assert_target(target)
            if time.monotonic() >= expires_at:
                fill_diagnostic(reason='expired')
                return False
            fill_diagnostic('write', 'write_unconfirmed')
            result = _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                'function(i,v){return this.write(i,v)}', (i, f['value'])).get('value')
            fill_diagnostic('readback', 'write_unconfirmed',
                            confirmed=isinstance(result, dict) and result.get('written') is True)
            if not isinstance(result, dict) or result != {'written': True, 'valid': True}:
                # Fixed booleans from the original write boundary only. No values,
                # exception strings, retargeting or retry after a partial setter.
                if isinstance(result, dict) and result.get('written') is True:
                    try:
                        checks = _invoke(target.supervisor, target.leaf_sid, target.leaf_guard,
                            'function(){return this.lastWriteChecks()}').get('value')
                    except Exception:
                        checks = None
                    if (isinstance(checks, dict) and
                            set(checks) == {'guard', 'documentFocus', 'targetFocus'} and
                            all(type(v) is bool for v in checks.values())):
                        if not checks['guard']:
                            fill_diagnostic(reason='guard_refused')
                        elif not checks['documentFocus']:
                            fill_diagnostic(reason='document_focus_lost')
                        elif not checks['targetFocus']:
                            fill_diagnostic(reason='unexpected_focus')
                return False
            fill_diagnostic('revalidate', 'guard_refused')
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
