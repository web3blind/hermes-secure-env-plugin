"""Public component, synthetic DOM/values, disposable Chromium only."""
from pathlib import Path
import time
import pytest
from test_nested_code import nested as nested, setup_chain
from secure_env_ingress import code_targets as codes

# Synthetic multi-cell CDP checks can exceed 20s on a loaded host. This
# fixture budget stays below production code TTL; no runtime deadline changes.
FILL_SECONDS = 60

MARKUP = '<form id="hk-login-form"><input type="email" style="display:none"><input type="password" style="display:none"><div class="login__smscode-container login_container"><div class="smscode__input-wrapper"><div class="js-sms__code__inputs"><input id="smscode" name="smscode" placeholder="Введите код" min="6" style="display:none"></div></div></div><button type="button" class="hk-login-btn">Login</button></form>'

def prepare(nested):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', MARKUP)
    leaf.evaluate('window.o={};window.clicked=0;window.HKSEC={validate2fa:()=>true};window.$=()=>({add(){return this},click(){window.clicked++}})')
    leaf.evaluate(Path(__file__).with_name('fixtures').joinpath('hostkey-public-otp.js').read_text())
    leaf.wait_for_timeout(150)
    return origin, leaf


def test_original_component_fill(nested):
    origin, leaf = prepare(nested)
    targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
    assert len(targets) == 1
    target = targets[0]
    try:
        assert codes.fill(target, '123456', time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('document.querySelector("#smscode").value === "123456"')
        assert leaf.evaluate('o.otpHandler.isVerifying && o.otpHandler.inputs.every(e=>e.disabled && e.classList.contains("filled"))')
        leaf.wait_for_timeout(350)
        assert leaf.evaluate('window.clicked === 1')
    finally:
        codes.release(target)

@pytest.mark.parametrize('attack', [
    'o.otpHandler.inputs[0].replaceWith(o.otpHandler.inputs[0].cloneNode())',
    'o.otpHandler.inputs[0].classList.remove("otp-digit-input");o.otpHandler.inputs[0].classList.add("otp-digit-input")',
    'document.querySelector("#smscode").setAttribute("min","5");document.querySelector("#smscode").setAttribute("min","6")',
    'document.querySelector("form").setAttribute("action","/other")',
])
def test_retained_group_attack(nested, attack):
    origin, leaf = prepare(nested)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        leaf.evaluate(attack)
        with pytest.raises(ValueError):
            codes.fill(target, '123456', time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('o.otpHandler.inputs.every(e=>e.value==="")')
    finally:
        codes.release(target)

@pytest.mark.parametrize('length', [5,7])
def test_group_wrong_length(nested, length):
    origin, leaf = prepare(nested)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        with pytest.raises(ValueError):
            codes.fill(target, '1'*length, time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('o.otpHandler.inputs.every(e=>e.value==="")')
    finally:
        codes.release(target)

@pytest.mark.parametrize('attack', [
    'o.otpHandler.otpWrapper.className="option-segmented-wrapper"',
    'o.otpHandler.otpWrapper.setAttribute("aria-label","Payment card code")',
    'o.otpHandler.inputs[0].name="promo"',
])
def test_lookalike_refuses(nested, attack):
    origin, leaf = prepare(nested)
    leaf.evaluate(attack)
    assert codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent) == []


def component(leaf):
    leaf.evaluate('window.o={};window.clicked=0;window.HKSEC={validate2fa:()=>true};window.$=()=>({add(){return this},click(){window.clicked++}})')
    leaf.evaluate(Path(__file__).with_name('fixtures').joinpath('hostkey-public-otp.js').read_text())
    leaf.wait_for_timeout(150)


def checked_component(leaf):
    assert leaf.evaluate('document.querySelector("#smscode").value === "123456"')
    assert leaf.evaluate('o.otpHandler.isVerifying && o.otpHandler.inputs.every(e=>e.disabled)')
    leaf.wait_for_timeout(350)
    assert leaf.evaluate('window.clicked === 1')


def test_registered_original_component(nested, tmp_path, monkeypatch):
    from test_nested_code import test_registered_nested_https as run
    run(nested, ('parent.test', 'parent.test'), True, tmp_path, monkeypatch,
        markup=MARKUP, setup_hook=component, synthetic_code='123456', completion_check=checked_component)


def generic_markup(n, evidence):
    controls='<input type="text" maxlength="1" autocomplete="off">'*n
    if evidence=='native':
        controls=controls.replace('autocomplete="off"','autocomplete="one-time-code"')
        return '<form><div>'+controls+'</div></form>'
    if evidence=='class':
        return '<form><div class="otp-widget">'+controls+'</div></form>'
    if evidence=='name':
        controls=controls.replace('<input ', '<input name="otp" ')
        return '<form><div>'+controls+'</div></form>'
    if evidence=='linked':
        return '<form><span id="heading">Verification code</span><div aria-labelledby="heading">'+controls+'</div></form>'
    return '<form><div aria-label="Verification code">'+controls+'</div></form>'


@pytest.mark.parametrize('n',[4,5,6,8,10,16])
@pytest.mark.parametrize('evidence',['native','name','class','linked','label'])
def test_variable_group(nested,n,evidence):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', generic_markup(n,evidence))
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    try:
        value=('A!7&z=R9Q@L2M#N4')[:n]
        assert len(value)==n
        assert codes.fill(target,value,time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('(v)=>Array.from(document.querySelectorAll("input")).map(e=>e.value).join("")===v',value)
    finally:
        codes.release(target)


@pytest.mark.parametrize('attack',[
    'document.querySelector("#heading").firstChild.data="Payment code";document.querySelector("#heading").firstChild.data="Verification code"',
    'document.querySelector("div").setAttribute("aria-labelledby","other");document.querySelector("div").setAttribute("aria-labelledby","heading")',
    'document.querySelector("div").replaceWith(document.querySelector("div").cloneNode(true))',
    'document.querySelector("form").replaceWith(document.querySelector("form").cloneNode(true))',
    'const d=document.querySelector("div").appendChild(document.createElement("input"));d.maxLength=1;d.remove()',
    'const d=document.querySelector("div").appendChild(document.createElement("input"));d.maxLength=1',
])
def test_group_evidence_sticky(nested,attack):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', generic_markup(6,'linked'))
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    try:
        leaf.evaluate(attack)
        with pytest.raises(ValueError):
            codes.fill(target,'123456',time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('markup',[
    '<form><div aria-label="Verification code">'+'<input maxlength="1">'*3+'</div></form>',
    '<form><div aria-label="Verification code">'+'<input maxlength="1">'*17+'</div></form>',
    '<form><div class="options-widget">'+'<input maxlength="1" inputmode="numeric">'*6+'</div></form>',
    generic_markup(6,'label').replace('<input ', '<input name="password" ',1),
    generic_markup(6,'label').replace('<input ', '<input name="cc-csc" ',1),
    generic_markup(6,'label').replace('</div>','<input name="unrelated"></div>'),
])
def test_invalid_generic_group(nested,markup):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',markup)
    assert codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)==[]


def test_competing_same_form_groups(nested):
    origin,leaf=setup_chain(nested)
    markup=generic_markup(6,'label').replace('</form>','')+generic_markup(6,'class').replace('<form>','')
    leaf.evaluate('(html)=>document.body.innerHTML=html',markup)
    with pytest.raises(ValueError,match='ambiguous code form'):
        codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)


@pytest.mark.parametrize('n',[4,5,6,8,10,16])
@pytest.mark.parametrize('numeric',[False,True])
def test_variable_handler(nested,n,numeric):
    origin,leaf=setup_chain(nested)
    markup=generic_markup(n,'label').replace('</form>',f'<input type="hidden" name="otp" min="{n}"></form>')
    leaf.evaluate('(html)=>document.body.innerHTML=html',markup)
    leaf.evaluate('''()=>{const digits=Array.from(document.querySelectorAll('div input')), canonical=document.querySelector('input[type=hidden]');
      digits.forEach((e,i)=>e.addEventListener('input',()=>{
        e.classList.add('filled');e.classList.remove('error');
        canonical.value=digits.map(d=>d.value).join('');canonical.dispatchEvent(new Event('input',{bubbles:true}));canonical.setAttribute('min',digits.length);
        if(i+1<digits.length)digits[i+1].focus();else digits.forEach(d=>d.disabled=true);
      }));}''')
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    try:
        value=('1234567890123456' if numeric else 'A!7&z=R9Q@L2M#N4')[:n]
        assert codes.fill(target,value,time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('(v)=>document.querySelector("input[type=hidden]").value===v',value)
        assert leaf.evaluate('Array.from(document.querySelectorAll("div input")).every(e=>e.disabled)')
    finally:
        codes.release(target)


@pytest.mark.parametrize('mode',['open','closed'])
def test_group_shadow_root(nested,mode):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(args)=>{document.body.innerHTML="";window.fixtureRoot=document.body.appendChild(document.createElement("div")).attachShadow({mode:args.mode});fixtureRoot.innerHTML=args.html}',{'mode':mode,'html':generic_markup(6,'linked')})
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    try:
        assert codes.fill(target,'A!7&z=',time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('Array.from(fixtureRoot.querySelectorAll("input")).map(e=>e.value).join("")==="A!7&z="')
    finally:
        codes.release(target)


def test_groups_in_separate_forms(nested):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',generic_markup(4,'class')+generic_markup(6,'label'))
    targets=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)
    try:
        assert len(targets)==2
        assert [len(t.controls) for t in targets]==[4,6]
    finally:
        for target in targets:
            codes.release(target)


@pytest.mark.parametrize('phase',['before','input'])
@pytest.mark.parametrize('variant',['insert','remove','link_history','id_history','text_history'])
def test_late_linked_competing_group(nested, phase, variant):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html', generic_markup(6,'class').replace(
        '</form>', '<span id="heading">Verification code</span></form>'))
    target = codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    attack = '''()=>{
      const form=document.querySelector('form'), source=document.querySelector('#heading');
      const wrapper=document.createElement('section'), group=wrapper.appendChild(document.createElement('div'));
      group.setAttribute('aria-labelledby','heading');
      group.innerHTML='<input maxlength="1">'.repeat(6);
      form.appendChild(wrapper);
      if(VARIANT==='link_history'){group.setAttribute('aria-labelledby','ordinary');group.removeAttribute('aria-labelledby');}
      if(VARIANT==='id_history'){source.id='ordinary';source.id='heading';}
      if(VARIANT==='text_history'){source.firstChild.data='Ordinary';source.firstChild.data='Verification code';}
      if(VARIANT!=='insert')wrapper.remove();
    }'''.replace('VARIANT',repr(variant))
    try:
        if phase=='before':
            leaf.evaluate(attack)
            with pytest.raises(ValueError):
                codes.assert_target(target)
            with pytest.raises(ValueError):
                codes.fill(target,'123456',time.monotonic()+FILL_SECONDS)
        else:
            leaf.evaluate('(attack)=>document.querySelector("input").addEventListener("input",eval("("+attack+")"),{once:true})',attack)
            assert not codes.fill(target,'123456',time.monotonic()+FILL_SECONDS)
        assert leaf.evaluate('(phase)=>Array.from(document.querySelector(".otp-widget").children).every((e,i)=>e.value===(phase==="input"&&i===0?"1":""))',phase)
    finally:
        codes.release(target)


def test_late_noncode_linked_group_allowed(nested):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',generic_markup(6,'class').replace('</form>','<span id="ordinary">Ordinary</span></form>'))
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)[0]
    try:
        leaf.evaluate('()=>{const div=document.createElement("div");div.setAttribute("aria-labelledby","ordinary");div.innerHTML="<input maxlength=1>".repeat(6);document.querySelector("form").appendChild(div);div.remove()}')
        assert codes.fill(target,'123456',time.monotonic()+FILL_SECONDS)
    finally:
        codes.release(target)


@pytest.mark.parametrize('evidence',['native','label'])
def test_payment_context_excluded(nested,evidence):
    origin,leaf=setup_chain(nested)
    leaf.evaluate('(html)=>document.body.innerHTML=html',generic_markup(6,evidence).replace('<form>','<form aria-label="Payment card authentication">'))
    assert codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent)==[]
