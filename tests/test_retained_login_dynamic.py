"""Real registered LOGIN dispatch, native handlers and public MIT React 18."""

from pathlib import Path
import pytest
from test_retained_login_browser import (
    browser as browser,
    env as env,
    backend,
    registered,
)
from secure_env_ingress import login_fill as lf


def test_native_own_dispatch(env, monkeypatch):
    env.page.evaluate("""() => {
      const p=document.querySelector('#p'), f=p.form;
      f.insertAdjacentHTML('beforeend','<button disabled>Sign in</button>');
      p.addEventListener('focus',()=>{p.classList.add('focused');f.classList.add('focused')});
      p.addEventListener('input',()=>{
        p.setAttribute('value',p.value);p.setAttribute('aria-invalid','false');
        p.classList.add('filled');f.querySelector('button').disabled=false;
      });
    }""")
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert env.page.evaluate('!document.querySelector("button").disabled')


@pytest.mark.parametrize("updater", [False, True])
def test_react18_controlled_password(env, monkeypatch, updater):
    fixtures = Path(__file__).parent / "fixtures"
    env.page.add_script_tag(
        content=(fixtures / "react-18.3.1.production.min.js").read_text()
    )
    env.page.add_script_tag(
        content=(fixtures / "react-dom-18.3.1.production.min.js").read_text()
    )
    env.page.add_script_tag(content=(fixtures / "react-input-updater.js").read_text())
    env.page.evaluate("flag=>window.useUpdater=flag", updater)
    env.page.evaluate("""() => {
      document.body.innerHTML='<div id="root"></div>';
      function Login(){const [v,set]=React.useState('');const [focus,setFocus]=React.useState(false);
        return React.createElement('form',{action:'/signin'},
          React.createElement('input',{id:'u',autoComplete:'username',defaultValue:'account@example.test'}),
          React.createElement('input',{id:'p',name:'password',type:'password',autoComplete:'current-password',
            value:v,className:focus?'focused':'', 'aria-invalid':v?'false':'true',
            onFocus:()=>ReactDOM.flushSync(()=>setFocus(true)),
            onChange:e=>{window.reconciled=(window.reconciled||0)+1;if(window.useUpdater)wt(e.target,undefined,undefined,undefined,undefined,undefined,'password',e.target.name);ReactDOM.flushSync(()=>set(e.target.value))}}),
          React.createElement('button',{disabled:!v},'Sign in'));
      }
      ReactDOM.flushSync(()=>ReactDOM.createRoot(document.querySelector('#root')).render(React.createElement(Login)));
    }""")
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert env.page.evaluate("window.reconciled===1")
    assert env.page.evaluate(
        'document.querySelector("#p").defaultValue===document.querySelector("#p").value&&!document.querySelector("button").disabled'
    )


@pytest.mark.parametrize("event", ["focus", "input"])
@pytest.mark.parametrize(
    "attack",
    [
        'p.form.action="/evil";p.form.action="/signin"',
        'document.querySelector("#u").value="other-account"',
        'p.name="otp";p.name=""',
        "p.replaceWith(p.cloneNode(true))",
        "document.body.append(p)",
        'p.classList.add("hidden");p.classList.remove("hidden")',
        'p.setAttribute("value","other");p.setAttribute("value",p.value)',
        'p.type="text";p.type="password"',
        'p.setAttribute("aria-invalid","true");p.setAttribute("aria-invalid","false");p.setAttribute("aria-invalid","true")',
    ],
)
def test_own_dispatch_rejects_conflicts(env, monkeypatch, event, attack):
    env.page.evaluate(
        '(a)=>{const p=document.querySelector("#p");p.addEventListener(a.event,()=>{'
        + attack
        + "},{once:true})}",
        {"event": event},
    )
    handle, _ = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == ("target_refused" if event == "focus" else "unknown"), (
        result
    )


@pytest.mark.parametrize(
    "mutation",
    [
        'p.classList.add("focused");p.classList.remove("focused")',
        'p.setAttribute("aria-invalid","false");p.removeAttribute("aria-invalid")',
        'p.setAttribute("value", "");p.removeAttribute("value")',
    ],
)
def test_waiting_changes_are_not_own_dispatch(env, monkeypatch, mutation):
    handle, resolved = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    try:
        env.page.evaluate('()=>{const p=document.querySelector("#p");' + mutation + "}")
        assert lf.fill_login(target, handle, lambda: None)["status"] == "target_refused"
        assert not resolved
    finally:
        target.lease.close()


@pytest.mark.parametrize(
    "css,selector",
    [
        ("input[aria-invalid=false]{color:red}", None),
        ('.focused::before{content:"OTP"}', None),
        (".focused{opacity:0}", None),
        ("", "form input#p"),
    ],
)
def test_dynamic_unknown_dependencies_refuse(env, monkeypatch, css, selector):
    if css:
        env.page.add_style_tag(content=css)
    env.page.evaluate(
        'document.querySelector("#p").addEventListener("focus",e=>e.target.classList.add("focused"))'
    )
    handle, _ = backend(env, monkeypatch)
    result = registered(
        env, monkeypatch, handle, **({"field_selector": selector} if selector else {})
    )
    assert result["status"] == "target_refused", result
    assert env.page.evaluate("window.writes===0")


def test_presentation_styles_and_native_password_value(env, monkeypatch):
    from agent.vault_backends.local import LocalLoginBackend

    env.page.add_style_tag(
        content=".focused{outline-color:blue}.filled{border-color:green}"
    )
    env.page.evaluate("""()=>{const p=document.querySelector('#p');
      p.addEventListener('focus',()=>p.classList.add('focused'));
      p.addEventListener('input',()=>{p.classList.add('filled');p.setAttribute('value',p.value)})
    }""")
    handle, _ = backend(env, monkeypatch)
    # Passwords are not OTPs: spaces, punctuation and non-ASCII remain literal.
    value = "  пароль synthetic 🔒 !  "
    monkeypatch.setattr(LocalLoginBackend, "resolve_password", lambda self, h: value)
    result = registered(env, monkeypatch, handle, field_selector="#p")
    assert result["status"] == "filled", result
    assert env.page.evaluate('(v)=>document.querySelector("#p").value===v', value)
