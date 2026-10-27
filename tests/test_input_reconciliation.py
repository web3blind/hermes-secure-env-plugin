"""Real public React input updater on synthetic numeric OTP cells."""
from pathlib import Path
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_submit_state import prepare as base_prepare, spec
from secure_env_ingress import code_targets as codes
from secure_env_ingress.bound_cdp import fill_diagnostic_scope


def prepare(leaf, paint=False):
    base_prepare(leaf, wrapper_tag="span" if paint else "div")
    source=Path(__file__).with_name('fixtures')/'react-input-updater.js'
    leaf.add_script_tag(content=source.read_text())
    leaf.evaluate('''()=>{
      window.originalCells=[...document.querySelectorAll('input')];
      window.reconcileCell=(e,active)=>{
        e.style.caretColor=active?'auto':'transparent';
        wt(e,undefined,undefined,undefined,undefined,undefined,'text',e.name);
      };
      for(const e of originalCells){
        e.inputMode='numeric';e.pattern='[0-9]*';
        e.style.cssText='font: 16px Arial; width: 28px; height: 32px; padding: 2px; border: 1px solid gray; box-sizing: border-box; caret-color: transparent';
        e.addEventListener('focus',()=>reconcileCell(e,true));
        e.addEventListener('blur',()=>reconcileCell(e,false));
      }
    }''')
    if paint:
        leaf.add_style_tag(content=Path(__file__).with_name('fixtures').joinpath('layered-otp-paint.css').read_text())
        leaf.evaluate('''()=>{
          for(const e of originalCells){
            e.parentElement.className='cell-shell';
            e.parentElement.dataset.testid='cell-shell';
            e.parentElement.dataset.disabled='false';
            e.setAttribute('tabindex','0');
            e.parentElement.style.cssText='display: inline-block; border: 1px solid gray';
            e.addEventListener('focus',()=>e.parentElement.classList.add('fixture-focus'));
            e.addEventListener('blur',()=>e.parentElement.classList.remove('fixture-focus'));
            e.addEventListener('input',()=>{e.parentElement.classList.add('fixture-focus');reconcileCell(e,true)});
          }
          const find=rules=>{for(const r of rules){if(r.selectorText==='.fixture-focus')return r;
            if(r.cssRules){const found=find(r.cssRules);if(found)return found}}};
          window.fixturePaintRule=find(document.styleSheets[0].cssRules);
          originalCells[0].focus();
        }''')


@pytest.mark.parametrize('metadata_canary', [False, True])
@pytest.mark.parametrize('paint', [False, True])
def test_real_updater_before_and_during_fill(nested, metadata_canary, paint):
    origin,leaf=setup_chain(nested)
    prepare(leaf, paint=paint)
    if paint:
        assert leaf.evaluate('''()=>{
          const rules=[...document.styleSheets[0].cssRules];
          return rules.filter(r=>r.type===0).length===63 &&
            rules.filter(r=>r.type===1).length===124 &&
            rules.filter(r=>r.type===4).length===4 &&
            rules.filter(r=>r.type===5).length===17 &&
            rules.filter(r=>r.type===7).length===14 &&
            originalCells.every(e=>e.getAttribute('tabindex')==='0' &&
              e.parentElement.dataset.testid==='cell-shell' &&
              e.parentElement.dataset.disabled==='false') &&
            document.activeElement===originalCells[0] &&
            originalCells.filter(e=>e.parentElement.classList.contains('fixture-focus')).length===1;
        }''')
    if metadata_canary:
        leaf.evaluate('''()=>new Promise(resolve=>{
          const frame=document.createElement('iframe');frame.style.display='none';
          frame.onload=resolve;frame.src='https://parent.test/empty-service';
          document.body.append(frame);
        })''')
    leaf.evaluate("originalCells.forEach(e=>e.addEventListener('input',()=>reconcileCell(e,true)))")
    target=codes.discover(origin,'Synthetic React bookkeeping',nested.sup.task_id,
                          parent=nested.parent,target_spec=spec())[0]
    try:
        leaf.evaluate('(paint)=>{reconcileCell(originalCells[0],true);if(paint)originalCells[0].parentElement.classList.add("fixture-focus")}', paint)
        with fill_diagnostic_scope() as diagnostic:
            result=codes.fill(target,'123456',time.monotonic()+60)
        assert result is True, diagnostic
        assert leaf.evaluate("[...document.querySelectorAll('input')].every((e,i)=>e===originalCells[i]&&e.name==='code'+i&&e.type==='text'&&!e.hasAttribute('value'))")
        assert leaf.evaluate("originalCells.map(e=>e.value).join('')")=='123456'
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack', [
    "e.name='password';e.name=n",
    "e.name='';e.name='code1';e.name=n",
    "e.type='password';e.type='text'",
    "e.style.display='none';e.style.display=''",
    "e.style.visibility='hidden';e.style.visibility=''",
    "e.style.setProperty('--transient-layout','none');e.style.removeProperty('--transient-layout')",
    "e.style.width='1px';e.style.width='28px'",
    "e.setAttribute('style',e.getAttribute('style')+';width:28px');e.style.width='28px'",
    "e.readOnly=true;e.readOnly=false",
    "e.autocomplete='current-password';e.autocomplete='one-time-code'",
    "const p=e.parentNode;document.body.append(e);p.append(e)",
    "e.replaceWith(e.cloneNode())",
    "const c=e.cloneNode();document.body.append(c);c.remove()",
    "e.setAttribute('aria-labelledby','foreign');e.removeAttribute('aria-labelledby')",
])
def test_reconciliation_does_not_hide_history(nested, attack):
    origin, leaf = setup_chain(nested)
    prepare(leaf)
    target = codes.discover(origin, 'Synthetic refusal', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate('(attack)=>{const e=originalCells[0],n=e.name;reconcileCell(e,true);eval(attack)}', attack)
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('case', ['split', 'complex', 'paint'])
def test_unsupported_reconciliation_refuses(nested, case):
    origin, leaf = setup_chain(nested)
    prepare(leaf)
    target_spec = spec()
    if case == 'complex':
        for field in target_spec['fields']:
            field['selector'] = 'form '+field['selector']
    target = codes.discover(origin, 'Synthetic unsupported', nested.sup.task_id,
                            parent=nested.parent, target_spec=target_spec)[0]
    try:
        if case == 'split':
            leaf.evaluate("originalCells[0].name=''")
            leaf.evaluate("originalCells[0].name='code0'")
        elif case == 'paint':
            leaf.evaluate("originalCells[0].parentElement.className='focus-marker'")
        else:
            leaf.evaluate('reconcileCell(originalCells[0],true)')
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack', [
    "s.classList.add('fixture-focus','password');s.classList.remove('password')",
    "s.classList.add('unknown-focus');s.classList.remove('unknown-focus')",
    "s.dataset.disabled='true';s.dataset.disabled='false'",
    "s.dataset.testid='foreign';s.dataset.testid='cell-shell'",
    "s.classList.remove('cell-shell');s.classList.add('cell-shell')",
    "fixturePaintRule.parentRule.deleteRule(0)",
    "const p=fixturePaintRule.parentRule,t=fixturePaintRule.cssText;p.deleteRule(0);p.insertRule(t,0)",
    "document.styleSheets[0].disabled=true",
    "s.style.visibility='hidden';s.style.visibility=''",
    "s.style.display='none';s.style.display='inline-block'",
    "s.style.width='200px';s.style.width=''",
    "s.setAttribute('aria-label','Password');s.removeAttribute('aria-label')",
    "s.setAttribute('id','label-source');e.setAttribute('aria-labelledby','label-source')",
    "const p=s.parentNode;document.body.append(s);p.append(s)",
    "s.replaceWith(s.cloneNode(true))",
    "const f=e.form;f.replaceWith(f.cloneNode(true))",
    "const f=document.createElement('iframe');s.append(f);f.remove()",
    "const c=e.cloneNode();s.append(c);c.remove()",
    "document.styleSheets[0].insertRule('.fixture-focus { display:none }',0)",
    "fixturePaintRule.style.boxShadow='0 0 0 50px red'",
    "document.documentElement.style.setProperty('--fixture-ring-size','50px')",
    "const t=document.querySelector('style');t.textContent+=' .fixture-focus{visibility:hidden}';t.textContent=t.textContent.replace(' .fixture-focus{visibility:hidden}','')",
])
def test_witnessed_paint_history_refuses(nested, attack):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    target = codes.discover(origin, 'Synthetic paint refusal', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate('(attack)=>{const e=originalCells[0],s=e.parentElement;eval(attack)}', attack)
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('rule', [
    '',
    '.fixture-focus { display:none; border-color:red; box-shadow:0 0 0 2px red }',
    '.fixture-focus input { visibility:hidden }',
    '.fixture-focus { border-color:red; box-shadow:0 0 0 50px red }',
    '.fixture-focus { border-color:red; box-shadow:0 0 0 2px red } .fixture-focus input { width:1px }',
])
def test_no_original_paint_witness_refuses(nested, rule):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.evaluate('(rule)=>document.querySelector("style").textContent=rule', rule)
    target = codes.discover(origin, 'Synthetic unwitnessed paint', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate("()=>{const s=originalCells[0].parentElement;s.classList.add('fixture-focus');s.classList.remove('fixture-focus')}")
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('inspection', [False, True])
def test_shared_constructor_default_keeps_reconciliation_disabled(nested, inspection):
    # Shared card consumers and legacy callers omit the new internal option.
    from secure_env_ingress.nested_code import _GUARD
    _, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    assert leaf.evaluate('''({source,inspection})=>{
      const construct=eval('('+source+')');
      const guard=construct(originalCells.slice(),inspection,[document],null,null);
      try {
        if(!guard.valid())throw Error('fixture not initially valid');
        reconcileCell(originalCells[0],true);
        originalCells[0].parentElement.classList.add('fixture-focus');
        return guard.valid()===false && originalCells.every(e=>!e.value);
      } finally {guard.close()}
    }''', {'source': _GUARD, 'inspection': inspection})


@pytest.mark.parametrize('extra', [
    '@media (min-width: 1px) { .fixture-focus { color: red } }',
    '@supports (display: block) { .fixture-focus { color: red } }',
    '@layer other { .fixture-focus:hover { color: red } }',
    '.fixture-focus + span { display:none }',
    '.other:has(.fixture-focus) { display:none }',
    '[class] { color: red }',
    '[class*="focus"] { color: red }',
    r'.fixture-\66 ocus { display:none }',
    '.outer { & .fixture-focus { display:none } }',
])
def test_layered_relevant_dependency_refuses(nested, extra):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.add_style_tag(content=extra)
    assert_paint_refusal(nested, origin, leaf)


def assert_paint_refusal(nested, origin, leaf):
    try:
        target = codes.discover(origin, 'Synthetic unsupported paint', nested.sup.task_id,
                                parent=nested.parent, target_spec=spec())[0]
    except ValueError:
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
        return
    try:
        leaf.evaluate("originalCells[0].parentElement.classList.remove('fixture-focus')")
        try:
            result = codes.fill(target, '123456', time.monotonic()+30)
        except ValueError:
            result = False
        assert result is False
        assert leaf.evaluate('originalCells.every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('markup', [
    '<span tabindex="0"></span>', '<span role="button"></span>',
    '<span contenteditable="true"></span>', '<button>Foreign</button>',
    '<iframe></iframe>',
])
def test_foreign_interactive_descendant_refuses(nested, markup):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.evaluate('(markup)=>originalCells[0].parentElement.insertAdjacentHTML("beforeend",markup)', markup)
    assert_paint_refusal(nested, origin, leaf)


@pytest.mark.parametrize('opaque', [False, True])
def test_import_dependency_refuses(nested, opaque):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    url = ('https://foreign.test' if opaque else origin) + '/paint-import.css'
    nested.context.route(url, lambda route: route.fulfill(
        content_type='text/css', body='.fixture-focus input { visibility: hidden }'))
    try:
        leaf.add_style_tag(content='@import url("'+url+'");')
        leaf.wait_for_function("[...document.styleSheets].some(s=>s.cssRules[0]?.styleSheet)")
        assert_paint_refusal(nested, origin, leaf)
    finally:
        nested.context.unroute(url)


def test_absent_original_token_is_not_inferred(nested):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    leaf.evaluate("originalCells[0].blur()")
    target = codes.discover(origin, 'Synthetic no anchor', nested.sup.task_id,
                            parent=nested.parent, target_spec=spec())[0]
    try:
        leaf.evaluate("originalCells[0].parentElement.classList.add('fixture-focus')")
        with pytest.raises(ValueError):
            codes.assert_target(target)
    finally:
        codes.release(target)


def test_readable_unrelated_import_does_not_disable_paint(nested):
    origin, leaf = setup_chain(nested)
    prepare(leaf, paint=True)
    url = origin + '/unrelated-paint-import.css'
    nested.context.route(url, lambda route: route.fulfill(
        content_type='text/css', body='@layer imported { .unrelated:hover { color: gray } }'))
    try:
        leaf.add_style_tag(content='@import url("'+url+'");')
        leaf.wait_for_function("[...document.styleSheets].some(s=>s.cssRules[0]?.styleSheet?.cssRules.length)")
        target = codes.discover(origin, 'Synthetic readable import', nested.sup.task_id,
                                parent=nested.parent, target_spec=spec())[0]
        try:
            assert codes.fill(target, '123456', time.monotonic()+60) is True
        finally:
            codes.release(target)
    finally:
        nested.context.unroute(url)
