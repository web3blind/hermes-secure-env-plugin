"""Native Vault destination policy in an explicitly retained plugin context.

No CSS parser, presentation snapshot, mutation observer or historical census.
The enclosing plugin retains task/profile/parent/approval/transport authority.
"""

# A per-boundary stamp is the same selection mechanism as native build_fill_js.
# Roots extend native document lookup only for the plugin's Shadow DOM support.
BOUNDARY_JS = r'''function(roots, nodes, password=false){
 const doc=document, origin=location.origin;
 const nonce=Array.from(crypto.getRandomValues(new Uint32Array(4)),x=>x.toString(16)).join('');
 let closed=false;
 const slots=nodes.map((e,i)=>{const slot=nonce+':'+i;e.setAttribute('data-hermes-vault-slot',slot);return slot});
 const find=i=>roots.filter(r=>r===doc||r.host?.isConnected).map(r=>r.querySelector('[data-hermes-vault-slot="'+slots[i]+'"]')).find(Boolean);
 // Only the selected password needs pre-resolution type/slot admission. OTP
 // and checkout choose their subset after resolution, as native Vault does;
 // unselected inspected candidates are not a competing-control census.
 const valid=()=>!closed&&document===doc&&location.origin===origin&&(!password||slots.length===0||!!find(0)&&find(0).type==='password');
 const norm=t=>String(t||'').trim().toLowerCase();
 return {document:doc,valid,
  close(){closed=true;for(let i=0;i<slots.length;i++)find(i)?.removeAttribute('data-hermes-vault-slot')},
  write(i,value){
   if(!valid())return {written:false,valid:false};
   const e=find(i);let written=false;
   try{
    if(e.tagName==='SELECT'){
     const want=norm(value),opt=Array.from(e.options).find(o=>[o.value,o.textContent].some(t=>norm(t)===want||norm(t)===want.replace(/^0/,'')));
     if(opt){e.value=opt.value;e.dispatchEvent(new Event('change',{bubbles:true}));written=true}
    }else{
     e.focus();
     if(e.tagName==='INPUT'||e.tagName==='TEXTAREA'){
      const proto=e.tagName==='INPUT'?HTMLInputElement.prototype:HTMLTextAreaElement.prototype;
      const setter=Object.getOwnPropertyDescriptor(proto,'value');
      if(setter?.set)setter.set.call(e,value);else e.value=value;
      e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText'}));
      e.dispatchEvent(new Event('change',{bubbles:true}));written=e.value.length>0;
     }else if(e.isContentEditable){
      e.textContent=value;e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText'}));
      e.dispatchEvent(new Event('change',{bubbles:true}));written=e.textContent.length>0;
     }
    }
   }catch(e){}
   return {written,valid:true};
  }
 };
}'''
