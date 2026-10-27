"""Selected frame composed ancestry is strict; service canaries stay metadata-only."""

import time
import pytest
from test_retained_login_browser import (
    browser as browser,
    env as env,
    backend,
    registered,
)
from secure_env_ingress import login_fill as lf


def loaded_frame(page, url):
    deadline = time.monotonic() + 20
    while True:
        frame = next((f for f in page.frames if f.url == url), None)
        if frame is not None:
            return frame
        assert time.monotonic() < deadline, "synthetic frame did not navigate: " + url
        page.wait_for_timeout(25)


def frame_login(env, origin, shadow=False):
    env.origin = origin
    env.browser.pages[origin + "/leaf"] = (
        "<form><input id=p type=password autocomplete=current-password></form>"
    )
    env.page.evaluate(
        'a=>{document.body.innerHTML="<section id=wrap></section>";const w=document.querySelector("#wrap");const r=a.shadow?w.attachShadow({mode:"closed"}):w;r.innerHTML="<iframe src=\\""+a.url+"\\"></iframe>";window.owner=r.querySelector("iframe")}',
        {"url": origin + "/leaf", "shadow": shadow},
    )
    env.page.wait_for_function("window.owner.contentWindow!==null")
    # Playwright waits for the actual routed destination, not an about:blank race.
    leaf = loaded_frame(env.page, origin + "/leaf")
    leaf.wait_for_selector("#p", state="attached")
    return leaf


@pytest.mark.parametrize("origin", ["https://a.test", "https://b.test"])
@pytest.mark.parametrize("shadow", [False, True])
@pytest.mark.parametrize(
    "hidden",
    [
        'owner.style.opacity="0"',
        'document.querySelector("#wrap").style.opacity="0"',
        'document.querySelector("#wrap").inert=true',
    ],
)
def test_hidden_selected_ancestry_before_resolution(
    env, monkeypatch, origin, shadow, hidden
):
    leaf = frame_login(env, origin, shadow)
    env.page.evaluate(hidden)
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "target_refused", result
    assert not resolved
    assert leaf.evaluate('document.querySelector("#p").value===""')


@pytest.mark.parametrize("origin", ["https://a.test", "https://b.test"])
def test_visible_selected_hidden_service(env, monkeypatch, origin):
    leaf = frame_login(env, origin, True)
    env.page.evaluate(
        '()=>{const f=document.createElement("iframe");f.style.opacity="0";f.src="about:blank";document.body.append(f)}'
    )
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert leaf.evaluate('document.querySelector("#p").value.length>0')


@pytest.mark.parametrize("hidden", [False, True])
def test_multilevel_oopif_selected_chain(env, monkeypatch, hidden):
    env.browser.pages["https://b.test/middle"] = (
        '<section id=middle><iframe src="https://c.test/deep"></iframe></section>'
    )
    env.browser.pages["https://c.test/deep"] = (
        "<form><input id=p type=password autocomplete=current-password></form>"
    )
    env.page.evaluate(
        "document.body.innerHTML='<section id=outer><iframe src=\"https://b.test/middle\"></iframe></section>'"
    )
    middle = loaded_frame(env.page, "https://b.test/middle")
    middle.wait_for_selector("iframe", state="attached")
    leaf = loaded_frame(env.page, "https://c.test/deep")
    leaf.wait_for_selector("#p", state="attached")
    if hidden:
        middle.evaluate('document.querySelector("#middle").style.opacity="0"')
    env.origin = "https://c.test"
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == ("target_refused" if hidden else "filled"), result
    assert len(resolved) == (0 if hidden else 1)
    assert leaf.evaluate('document.querySelector("#p").value.length>0') is not hidden


@pytest.mark.parametrize("phase", ["waiting", "focus"])
def test_selected_ancestry_transition(env, monkeypatch, phase):
    leaf = frame_login(env, "https://a.test")
    handle, resolved = backend(env, monkeypatch)
    if phase == "focus":
        leaf.evaluate(
            'document.querySelector("#p").onfocus=()=>{parent.document.querySelector("#wrap").style.opacity="0"}'
        )
        assert registered(env, monkeypatch, handle)["status"] == "target_refused"
    else:
        target = lf.discover(
            env.browser.sup.task_id, env.parent, env.origin, lambda: None
        )
        try:
            env.page.evaluate('document.querySelector("#wrap").style.opacity="0"')
            assert (
                lf.fill_login(target, handle, lambda: None)["status"]
                == "target_refused"
            )
            assert not resolved
        finally:
            target.lease.close()
    assert leaf.evaluate('document.querySelector("#p").value===""')
