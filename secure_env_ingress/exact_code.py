"""Closed public intent and value contracts for retained transient-code targets.

Selectors are discovery data, never execution source. Legacy callers keep their
4..16 ASCII policy. Explicit targets require a separate protected confirmation.
"""
from dataclasses import dataclass
import json
import re
from .unicode_contract import accepts_scalar, public_contract, validate_contract


@dataclass(frozen=True)
class ValuePolicy:
    charset: str
    exact_length: int
    multiline: bool = False

    def public(self):
        return {'charset': self.charset, 'exact_length': self.exact_length,
                'multiline': self.multiline}

    def accepts(self, value):
        if not isinstance(value, str) or len(value) != self.exact_length:
            return False
        if len(value.encode('utf-8', errors='surrogatepass')) > 16384:
            return False
        if self.charset == 'ascii_digits':
            return re.fullmatch(r'[0-9]+', value) is not None
        if self.charset == 'ascii_printable_no_space':
            return re.fullmatch(r'[!-~]+', value) is not None
        return all((c == '\n' and self.multiline) or
                   (accepts_scalar(ord(c)) and c not in '\r\n')
                   for c in value)


def selector(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 256 or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid target spec')
    return value


def validate_spec(spec, parent):
    if not isinstance(parent, str) or not parent or not isinstance(spec, dict):
        raise ValueError('invalid target spec')
    common = {'version', 'purpose', 'layout', 'validation'}
    layout = spec.get('layout')
    extra = {'fields'} if layout in ('single', 'ordered_cells') else {'group', 'field_selector', 'order', 'expected_count'}
    if set(spec) != common | extra or type(spec.get('version')) is not int or spec['version'] != 1 or spec.get('purpose') != 'transient_code':
        raise ValueError('invalid target spec')
    if layout in ('single', 'ordered_cells'):
        fields = spec['fields']
        if not isinstance(fields, list) or not (len(fields) == 1 if layout == 'single' else 1 <= len(fields) <= 100):
            raise ValueError('invalid target spec')
        for f in fields:
            if not isinstance(f, dict) or set(f) != {'selector'}:
                raise ValueError('invalid target spec')
            selector(f['selector'])
        count = len(fields)
    elif layout == 'indexed_cells':
        selector(spec['group'])
        selector(spec['field_selector'])
        count = spec['expected_count']
        if spec['order'] != 'dom' or type(count) is not int or not 1 <= count <= 100:
            raise ValueError('invalid target spec')
    else:
        raise ValueError('invalid target spec')
    v = spec['validation']
    if (not isinstance(v, dict) or set(v) != {'charset', 'exact_length', 'multiline'} or
            v['charset'] not in ('ascii_digits', 'ascii_printable_no_space', 'unicode_text') or
            type(v['exact_length']) is not int or not 1 <= v['exact_length'] <= 100 or
            type(v['multiline']) is not bool or (v['multiline'] and (layout != 'single' or v['charset'] != 'unicode_text')) or
            (layout != 'single' and v['exact_length'] != count)):
        raise ValueError('invalid target spec')
    # Canonical roundtrip freezes caller containers and makes capability equality exact.
    return json.loads(json.dumps(spec, sort_keys=True))


def policy(spec):
    return ValuePolicy(**spec['validation'])


def descriptor(spec):
    result = {'version': 1, 'purpose': 'transient_code', 'layout': spec['layout'],
            'count': len(spec['fields']) if 'fields' in spec else spec['expected_count'],
            'validation': policy(spec).public(), 'confirmation_required': True}
    if spec['validation']['charset'] == 'unicode_text':
        result['unicode_contract'] = public_contract()
    return result


def validate_descriptor(d):
    unicode = isinstance(d, dict) and isinstance(d.get('validation'), dict) and d['validation'].get('charset') == 'unicode_text'
    keys = {'version', 'purpose', 'layout', 'count', 'validation', 'confirmation_required'}
    if unicode:
        keys.add('unicode_contract')
    if (not isinstance(d, dict) or set(d) != keys or
            type(d['version']) is not int or d['version'] != 1 or d['purpose'] != 'transient_code' or
            d['confirmation_required'] is not True or type(d['count']) is not int):
        raise ValueError('invalid descriptor')
    s = {k: d[k] for k in ('version', 'purpose', 'layout', 'validation')}
    if d['layout'] in ('single', 'ordered_cells'):
        if not 1 <= d['count'] <= 100:
            raise ValueError('invalid descriptor')
        s['fields'] = [{'selector': '#synthetic'}] * d['count']
    else:
        s.update(group='#synthetic', field_selector='input', order='dom', expected_count=d['count'])
    validate_spec(s, 'descriptor')
    if unicode:
        validate_contract(d['unicode_contract'])
    return d


def schema():
    selector = {'type': 'string', 'minLength': 1, 'maxLength': 256}
    common = {'version': {'type': 'integer', 'enum': [1]}, 'purpose': {'type': 'string', 'enum': ['transient_code']},
              'validation': {'type': 'object', 'additionalProperties': False, 'required': ['charset', 'exact_length', 'multiline'], 'properties': {
                  'charset': {'type': 'string', 'enum': ['ascii_digits', 'ascii_printable_no_space', 'unicode_text']},
                  'exact_length': {'type': 'integer', 'minimum': 1, 'maximum': 100}, 'multiline': {'type': 'boolean'}}}}
    variants = []
    for layout in ('single', 'ordered_cells', 'indexed_cells'):
        props = dict(common, layout={'type': 'string', 'enum': [layout]})
        if layout == 'indexed_cells':
            props.update(group=selector, field_selector=selector, order={'type': 'string', 'enum': ['dom']}, expected_count={'type': 'integer', 'minimum': 1, 'maximum': 100})
        else:
            props['fields'] = {'type': 'array', 'minItems': 1, 'maxItems': 1 if layout == 'single' else 100,
                               'items': {'type': 'object', 'additionalProperties': False, 'required': ['selector'], 'properties': {'selector': selector}}}
        variants.append({'type': 'object', 'additionalProperties': False, 'required': list(props), 'properties': props})
    return {'description': 'Exact retained transient-code intent; parent required. No secrets. Requires explicit HTTPS purpose confirmation. Legacy autodiscovery unchanged.', 'oneOf': variants}

# Native fallback pixels, interactive widgets and selected shadow hosts are not
# simple text editors, even when their contenteditable attribute says otherwise.
PLAIN_EDITOR_JS = r'''function(e,roots){
 const atomic='area,audio,br,button,canvas,embed,hr,iframe,img,input,link,meta,noscript,object,option,script,select,source,style,template,textarea,track,video,frame,a[href]';
 const nontext=/^(button|link|img|checkbox|radio|switch|slider|spinbutton|progressbar|combobox|listbox|option|menu|menuitem|tree|treeitem|grid|gridcell|application)$/;
 return e.namespaceURI==='http://www.w3.org/1999/xhtml'&&!e.matches(atomic)&&
   !(e.getAttribute('role')||'').trim().toLowerCase().split(/\s+/).some(r=>nontext.test(r))&&
   !roots.some(r=>r instanceof ShadowRoot&&r.host===e)&&
   ['plaintext-only','true'].includes(e.getAttribute('contenteditable'))&&e.isContentEditable&&
   !(e.parentElement||e.getRootNode().host)?.isContentEditable&&!e.children.length&&
   Array.from(e.childNodes).every(n=>n.nodeType===3);
}'''

# Value-free exporter: no stamps, document properties, or target attribute edits.
EXPORT_JS = r'''function(roots, controls='input,select,textarea,[contenteditable]'){
 const query=s=>roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
 const nodes=query(controls);
 const forms=query('form');
 const rows=nodes.flatMap((e,index)=>{
  const style=getComputedStyle(e);
  if(e.matches(':disabled')||e.readOnly||e.closest('[inert]')||
    ['hidden','submit','button','reset','file','image','checkbox','radio'].includes(e.type)||
    style.display==='none'||style.visibility!=='visible'||!e.getClientRects().length)return [];
  const root=e.getRootNode();
  const label=[...Array.from(e.labels||[],l=>l.textContent||''),e.getAttribute('aria-label')||'',
   ...(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>root.getElementById(id)?.textContent||''),
   e.getAttribute('placeholder')||'',e.getAttribute('title')||''].join(' ');
  return [{index,autocomplete:e.autocomplete||'',formIndex:e.form?forms.indexOf(e.form):null,
   maxLength:e.maxLength>0?e.maxLength:null,label,name:[e.name||'',e.id].join(' '),
   type:e.tagName==='SELECT'?'select':e.tagName==='TEXTAREA'?'textarea':e.tagName==='INPUT'?e.type:'plaintext',
   inputMode:e.inputMode||'',fieldName:e.name||'',rootIndex:roots.indexOf(root)}];
 });
 return {nodes,rows};
}'''


# Every field resolves exactly once across all retained roots in this document.
# Multiple matching documents are rejected by the traversal, never first-match.
RESOLVE_JS = r'''function(spec){
 const query=s=>this.roots.flatMap(r=>Array.from(r.querySelectorAll(s)));
 const rootLabel=(e,id)=>e.getRootNode().getElementById(id)?.textContent||'';
 let selected=[],group=null;
 if(spec.layout==='indexed_cells'){
  const groups=query(spec.group);if(!groups.length)return null;
  if(groups.length!==1)throw Error('ambiguous');group=groups[0];
  selected=Array.from(group.querySelectorAll(spec.field_selector));
  if(selected.length!==spec.expected_count)throw Error('membership');
 }else{
  const matches=spec.fields.map(f=>query(f.selector));
  if(matches.every(m=>!m.length))return null;
  if(matches.some(m=>m.length!==1))throw Error('ambiguous');
  selected=matches.map(m=>m[0]);
 }
 if(new Set(selected).size!==selected.length||!selected.length||selected.length>100||
   selected.some(e=>e.getRootNode()!==selected[0].getRootNode()))throw Error('scope');
 for(const e of selected){
  const form=e.matches('input,textarea,select')?e.form:e.closest('form');
  if(form&&new URL(form.action,document.baseURI).origin!==self.origin)throw Error('form origin');
  const row=this.rows.find(r=>this.nodes[r.index]===e);
  if(!row||!['text','tel','password','textarea','plaintext'].includes(row.type)||
    e.getAttribute('aria-disabled')==='true'||e.getAttribute('aria-readonly')==='true')throw Error('adapter');
  const parents=[];
  for(let p=e.parentElement||e.getRootNode().host;p&&p!==document.body;p=p.parentElement||p.getRootNode().host)parents.push(p);
  if(form&&!parents.includes(form))parents.push(form);
  const ancestry=[];for(const p of parents){
   ancestry.push(p.getAttribute('aria-label')||'',p.getAttribute('title')||'',p.getAttribute('name')||'',
    ...(p.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean).map(id=>rootLabel(p,id)));
  }
  const normalize=s=>String(s||'').replace(/([a-z])([A-Z])/g,'$1 $2').normalize('NFKC').toLowerCase();
  const ownName=normalize(row.name), ownLabel=normalize(row.label), ac=normalize(row.autocomplete);
  const otp=/one[ _-]*time[ _-]*(?:code|password)|\botp\b|\bpasscode\b|(?:verification|confirmation)[ _-]*code|код[ _-]*(?:подтверждения|верификации)|одноразов/.test([ownName,ownLabel,ac].join(' '));
  const dangerous=/captcha|promo|coupon|discount|gift|cvv|cvc|csc|card|credit|payment|billing|postal|zip|api[ _-]*(?:key|token)|(?:access|bearer|refresh|auth)[ _-]*token|jwt|(?:private|signing)[ _-]*key|seed|recovery|backup|credential|secret|секрет|ключ|восстанов/;
  const credential=/password|passwd|(?:^|[^a-z])pwd(?:$|[^a-z])|passphrase|парол|user[ _-]*name|email|e-mail|account[ _-]*name/;
  // Selected name/id and native autofill roles are stronger than caller intent.
  // OTP phrases/context cannot turn an actual email/password/key field into OTP.
  if(dangerous.test(ownName+' '+ownLabel)||credential.test(ownName))throw Error('purpose');
  const labelRole=ownLabel.replace(/one[ _-]*time[ _-]*password/g,'one time code')
    .replace(/(?:email|e-mail)[ _-]*(?:verification|confirmation)[ _-]*code/g,'verification code');
  if(credential.test(labelRole))throw Error('purpose');
  const context=normalize(ancestry.join(' '));
  if(dangerous.test(context)||(credential.test(context)&&!otp))throw Error('purpose');
  if(row.type==='password'&&!otp)throw Error('purpose');
  if(ac.split(/\s+/).some(t=>t&&!/^(off|on|one-time-code|section-[a-z0-9_-]+)$/.test(t)))throw Error('purpose');
  if(row.type==='plaintext'&&!(__PLAIN_EDITOR__)(e,this.roots))throw Error('editing host');
  if(spec.validation.multiline&&!['textarea','plaintext'].includes(row.type))throw Error('multiline');
  // Explicit cell authority comes from the confirmed count/value policy, not
  // a site maxlength repair. Retain actual capacity metadata and read back each
  // exact setter; truncating handlers/capacity conflicts fail closed.
  if(spec.layout!=='single'&&!['text','tel','password'].includes(row.type))throw Error('cell');
 }
 return {indices:selected.map(e=>this.nodes.indexOf(e)),rows:selected.map(e=>this.rows.find(r=>this.nodes[r.index]===e))};
}'''.replace('__PLAIN_EDITOR__', PLAIN_EDITOR_JS)
