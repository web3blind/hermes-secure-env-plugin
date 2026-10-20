"""Registered LOGIN regressions for restored account events and scoped CSS."""

import pytest
from test_retained_login_browser import (
    browser as browser,
    env as env,
    backend,
    registered,
)
from secure_env_ingress import login_fill as lf


@pytest.mark.parametrize("event", ["beforeinput", "input", "change"])
@pytest.mark.parametrize("stage", ["waiting", "focus"])
@pytest.mark.parametrize("source", ["#u", "#p", "form"])
def test_restored_account_event_is_sticky(env, monkeypatch, event, stage, source):
    # The shared fixture's document-wide counter includes the deliberate
    # username event. Observe only the password destination instead.
    env.page.evaluate("""() => {
      window.passwordInputs=0;
      document.querySelector('#p').addEventListener('input',()=>window.passwordInputs++);
    }""")
    mutation = """() => {
      const u=document.querySelector('#u'), original=u.value;
      u.value='other-account';
      document.querySelector(SOURCE).dispatchEvent(new Event(EVENT,{bubbles:true,composed:true}));
      u.value=original;
    }""".replace("EVENT", repr(event)).replace("SOURCE", repr(source))
    handle, resolved = backend(env, monkeypatch)
    if stage == "waiting":
        target = lf.discover(
            env.browser.sup.task_id, env.parent, env.origin, lambda: None
        )
        try:
            env.page.evaluate(mutation)
            result = lf.fill_login(target, handle, lambda: None)
            assert not resolved
        finally:
            target.lease.close()
    else:
        env.page.evaluate(
            'document.querySelector("#p").addEventListener("focus",' + mutation + ")"
        )
        result = registered(env, monkeypatch, handle)
    assert result["status"] == "target_refused", result
    expected_events = int(source == "#p" and event == "input")
    assert env.page.evaluate(
        '(n)=>window.passwordInputs===n&&document.querySelector("#p").value===""',
        expected_events,
    )


def test_scoped_focus_class_cannot_hide_password_label(env, monkeypatch):
    env.page.evaluate("""() => {
      const p=document.querySelector('#p');
      p.insertAdjacentHTML('beforebegin','<label for="p">Password</label>');
      p.addEventListener('focus',()=>p.form.classList.add('focused'));
    }""")
    env.page.add_style_tag(content="@scope (.focused) { label { display:none } }")
    assert env.page.evaluate(
        'Array.from(document.styleSheets).some(s=>Array.from(s.cssRules).some(r=>r.cssText.startsWith("@scope")))'
    )
    handle, _ = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "target_refused", result
    assert env.page.evaluate("window.writes===0")
