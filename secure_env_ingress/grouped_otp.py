"""Plugin-only, value-free evidence for an unnamed segmented OTP component."""

GROUP_JS = r'''function(e) {
  const w=e.parentElement, f=e.form, root=e.getRootNode();
  const code=v=>/\b(?:otp|totp|2fa|mfa|passcode)\b|verification[ _-]*code|one[ _-]*time[ _-]*code|sms[ _-]*code|код\s+(?:подтверждения|верификации)|одноразовый\s+код/i.test(String(v||'').replace(/[-_]/g,' '));
  // Match credential tokens, not substrings of unrelated component words.
  // Preserve each token view: acronym splitting can obscure a raw key token.
  const credential=/\b(?:password|promo|coupon|discount|cvv|cvc|csc|card|credit|payment|billing|postal|zip|api[ _-]*key|private[ _-]*key|seed|recovery|backup|user[ _-]*name)\b|парол|промо|купон|секрет|ключ|восстанов/i;
  const forbidden=v=>{
    const raw=String(v||'').replace(/[_-]/g,' ');
    const camel=raw.replace(/([a-z0-9])([A-Z])/g,'$1 $2');
    const acronym=raw.replace(/([A-Z]+)([A-Z][a-z])/g,'$1 $2').replace(/([a-z0-9])([A-Z])/g,'$1 $2');
    return [raw,camel,acronym].some(view=>credential.test(view));
  };
  if(!w||!w.isConnected||w.getRootNode()!==root)return null;
  const sources=(w.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>root.getElementById(id));
  if(sources.some(s=>!s))return null;
  const evidence=[w.className,w.id,w.getAttribute('aria-label'),...sources.map(s=>s.textContent)].join(' ');
  const digits=Array.from(w.children);
  const fieldEvidence=d=>[d.name,d.id,d.autocomplete,d.getAttribute('aria-label'),d.getAttribute('placeholder'),...Array.from(d.labels||[],l=>l.textContent)].join(' ');
  const context=[];for(let n=w;n;n=n.parentElement){context.push(n.id,n.className,n.getAttribute('aria-label'));if(n===f)break;}
  // Indexed code names are semantic group evidence, not a count of numeric fields.
  // Require exact zero-based DOM order and single ASCII digit constraints when
  // maxlength is absent. Never infer segmentation from inputmode alone.
  const indexed=digits.length>=4&&digits.length<=16&&digits.every((d,i)=>
    d.matches('input')&&d.name==='code-'+i&&d.inputMode==='numeric'&&
    ['[0-9]','[0-9]{1}'].includes(d.getAttribute('pattern')) &&
    (d.maxLength===1||!d.hasAttribute('maxlength')));
  const cell=d=>d.matches('input')&&(d.maxLength===1||indexed);
  if(!indexed&&!code(evidence)&&!digits.every(d=>code(fieldEvidence(d))))return null;
  if(digits.length>=4&&digits.length<=16&&digits.every(cell)&&
    forbidden(evidence+' '+context.join(' ')+' '+digits.map(fieldEvidence).join(' ')))return {forbidden:true};
  if(digits.length<4||digits.length>16||!digits.every(d=>d.matches('input')&&d.form===f&&d.getRootNode()===root&&
    ['text','tel'].includes(d.type)&&cell(d)&&!d.matches(':disabled')&&!d.readOnly&&
    !d.closest('[inert]')&&d.getAttribute('aria-disabled')!=='true'&&d.getAttribute('aria-readonly')!=='true'&&d.getClientRects().length&&getComputedStyle(d).visibility==='visible'&&
    !forbidden([d.name,d.id,d.getAttribute('aria-label'),d.getAttribute('placeholder'),...Array.from(d.labels||[],l=>l.textContent)].join(' '))&&
    ['','off','on','one-time-code'].includes(d.autocomplete)))return null;
  const canonicals=Array.from(f?f.elements:w.children).filter(c=>c.matches('input')&&c.getRootNode()===root&&
    (c.type==='hidden'||!c.getClientRects().length)&&code([c.name,c.id,c.autocomplete,c.getAttribute('aria-label'),c.getAttribute('placeholder')].join(' ')));
  if(canonicals.length>1||canonicals.some(c=>forbidden([c.name,c.id,c.getAttribute('placeholder')].join(' '))||c.getAttribute('min')!==String(digits.length)))return null;
  return {wrapper:w,digits,sources,canonical:canonicals[0]||null,numeric:indexed};
}'''
