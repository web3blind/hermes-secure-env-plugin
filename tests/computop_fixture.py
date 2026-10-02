"""Sanitized captured topology and byte-exact public assets; no convenient CSS.

Only field-label associations (omitted by the capture's attribute allowlist),
empty synthetic form authority and provider input-handler semantics are added.
URLs are served by the disposable browser router, never requested live.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).parent / 'fixtures' / 'computop'
MANIFEST = json.loads((ROOT / 'manifest.json').read_text())


def markup(origin='https://www.computop-paygate.com'):
    def render(row, field=None):
        tag = row['tag'].lower()
        attrs = dict(row.get('attributes', {}))
        if row.get('id'):
            attrs['id'] = row['id']
        if row.get('classes'):
            attrs['class'] = row['classes']
        if tag == 'img':
            attrs['src'] = row['source']
        if tag == 'label':
            attrs['for'] = field
        if tag == 'span' and row.get('classes') == 'custom-input-wrapper':
            field = next(c['id'] for c in row['children'] if c['tag'] == 'INPUT')
        at = ''.join(f' {k}="{html.escape(v, quote=True)}"' for k, v in attrs.items())
        if tag in ('input', 'img'):
            return f'<{tag}{at}>'
        # Captured label text included the asterisk child; preserve that child.
        text = html.escape(row.get('text', '').removesuffix('*'))
        children = ''.join(render(c, field) for c in row['children'])
        if tag == 'label':
            children = '<span>*</span>'
        return f'<{tag}{at}>{text}{children}</{tag}>'
    styles = ''.join(f'<link rel="stylesheet" href="{r["url"]}">' for r in MANIFEST if r['name'].endswith('.css'))
    return (styles + '<div class="iframe-wrapper" id="content"><form id="SSLForm" name="SSLForm">' + render(json.loads((ROOT / 'topology.json').read_text())) + '''
<input type="hidden" name="KKName"><input type="hidden" name="KKMonth"><input type="hidden" name="KKYear">
<label class="custom-checkbox-label"><input id="check_agb" type="checkbox">Accept card storage and open invoice payments</label>
<button class="custom-button-red">Pay</button></form></div>''').replace('https://www.computop-paygate.com', origin)


HANDLERS = r'''() => {
  window.submissions=0;
  document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submissions++});
  window.fieldEvents={};
  for(const e of document.querySelectorAll('input:not([type=hidden]):not([type=checkbox])')) {
    window.fieldEvents[e.id]={focus:0,input:0,change:0};
    for(const event of ['focus','input','change'])e.addEventListener(event,()=>window.fieldEvents[e.id][event]++);
  }
  // Public accounts-unified-main.js se()/ae() and valid VISA input branch.
  // KKName uses the property setter, not an invented attribute update.
  const pan=document.querySelector('#_KKnr');
  function se(){document.querySelectorAll('.brand').forEach(e=>e.style.display='none')}
  function ae(){se();document.querySelector('#brand_visa').style.display='flex'}
  pan.addEventListener('input',()=>{
    pan.value=pan.value.replace(/ /g,'').replace(/([0-9]{4})(?=[0-9])/g,'$1 ');
    ae();document.SSLForm.KKName.value='VISA';
  });
  pan.addEventListener('focus',()=>{if(pan.hasAttribute('data-pkn')){pan.value='';se()}});
  pan.addEventListener('blur',()=>{if(pan.hasAttribute('data-pkn')){pan.value=pan.getAttribute('data-pkn-masked');ae()}});
}'''


def overlay_attack(kind):
    """Astra's exact static overlays and indirect activation equivalents."""
    initial = 'transform:translateX(-200vw)'
    selector = '#cccvc:focus ~ .custom-input-info'
    if kind == 'mixed':
        selector = '#cccvc:focus ~ *'
        effect = 'transform:translateY(-0.25rem) scale(0.75)'
    elif kind == 'custom_property':
        initial = 'transform:var(--overlay-transform,translateX(-200vw))'
        effect = '--overlay-transform:translateY(-0.25rem) scale(0.75)'
    elif kind == 'opacity':
        initial = 'opacity:0'
        effect = 'opacity:1'
    elif kind == 'visibility':
        initial = 'visibility:hidden'
        effect = 'visibility:visible'
    else:
        raise ValueError('unknown synthetic attack')
    return ('#cccvc ~ .custom-input-info {'
            'position:fixed;left:0;top:0;right:auto;width:100vw;height:100vh;margin:0;'
            'background:black;z-index:10000;pointer-events:none;' + initial + ';}'
            + selector + '{' + effect + ';}')


def install(context):
    for row in MANIFEST:
        content_type = ('text/css' if row['name'].endswith('.css') else
                        'image/svg+xml' if row['name'].endswith('.svg') else 'font/woff2')
        context.route(row['url'], lambda r, row=row, ct=content_type: r.fulfill(
            body=(ROOT / row['name']).read_bytes(), content_type=ct))
    # Font references from exact fonts.css are relative to its routed public URL.
    # Everything else remains under the caller's deny/default synthetic router.


def ready(frame):
    frame.wait_for_function('Array.from(document.images).every(i=>i.complete && i.naturalWidth===45 && i.naturalHeight===20)')
    frame.evaluate('document.fonts.ready')
    frame.evaluate(HANDLERS)
