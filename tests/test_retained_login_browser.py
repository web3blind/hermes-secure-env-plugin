"""Real public stock capture → registered tool → synthetic isolated Chromium."""

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import urllib.request

import pytest

from secure_env_ingress import login_fill as lf


@pytest.fixture(scope="module")
def browser():
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from playwright.sync_api import sync_playwright

    with tempfile.TemporaryDirectory(
        dir=os.environ["TMPDIR"], prefix="lg-"
    ) as directory:
        proc = subprocess.Popen(
            [
                "/usr/bin/chromium",
                "--headless=new",
                "--no-sandbox",
                "--remote-debugging-port=0",
                "--user-data-dir=" + directory,
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            port = Path(directory) / "DevToolsActivePort"
            deadline = time.monotonic() + 20
            lines = []
            while len(lines) < 2 or not lines[0].isdigit():
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(0.05)
                lines = port.read_text().splitlines() if port.exists() else []
            endpoint = "http://127.0.0.1:" + lines[0]
            with urllib.request.urlopen(endpoint + "/json/version") as response:
                ws = json.load(response)["webSocketDebuggerUrl"]
            with sync_playwright() as pw:
                chrome = pw.chromium.connect_over_cdp(endpoint)
                context = chrome.new_context(ignore_https_errors=True)
                pages = {}
                context.route(
                    "**/*",
                    lambda r: r.fulfill(
                        body=pages.get(r.request.url, ""), content_type="text/html"
                    ),
                )
                first = context.new_page()
                pages["https://a.test/first"] = (
                    "<form><input id=p type=password autocomplete=current-password></form>"
                )
                first.goto("https://a.test/first")
                sup = CDPSupervisor("retained-login", ws)
                sup.start()
                with SUPERVISOR_REGISTRY._lock:
                    SUPERVISOR_REGISTRY._by_task[sup.task_id] = sup
                assert sup.focus_page("https://a.test")["ok"]
                try:
                    yield SimpleNamespace(
                        context=context, pages=pages, sup=sup, first=first
                    )
                finally:
                    sup.stop()
                    with SUPERVISOR_REGISTRY._lock:
                        SUPERVISOR_REGISTRY._by_task.pop(sup.task_id, None)
                    context.close()
                    chrome.close()
        finally:
            # Exact disposable process group only; never enumerate/kill shared Chrome.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.fixture
def env(browser, tmp_path, monkeypatch):
    from test_runtime_e2e import make_runtime

    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv("HERMES_HOME", str(home))
    browser.pages["https://a.test/login"] = (
        '<form action=/signin onsubmit="window.submitted=true;return false"><input id=u autocomplete=username><input id=p type=password autocomplete=current-password></form><script>window.writes=0;document.addEventListener("input",()=>window.writes++)</script>'
    )
    page = browser.context.new_page()
    page.goto("https://a.test/login")
    page.bring_to_front()  # Fixture-only initial selected page; plugin never activates.
    session = browser.context.new_cdp_session(page)
    parent = session.send("Target.getTargetInfo")["targetInfo"]["targetId"]
    session.detach()
    e = SimpleNamespace(
        browser=browser,
        page=page,
        parent=parent,
        home=home,
        settings=settings,
        origin="https://a.test",
        leaf=page,
    )
    try:
        yield e
    finally:
        page.close()


def backend(env, monkeypatch, origin=None, mode="login"):
    from agent.vault_store import VaultStore
    from agent.vault_backends.local import LocalLoginBackend

    secret = {
        "password": "Synthetic-Long-Password!",
        "identifier": "madeup@example.test",
        "identifier_type": "email",
    }
    if mode == "totp":
        secret["otp_secret"] = "JBSWY3DPEHPK3PXP"
    handle = (
        VaultStore(env.home / "vault")
        .add_item("login", "Synthetic login", secret, origin=origin or env.origin)
        .id
    )
    resolved = []
    method = "resolve_otp" if mode == "totp" else "resolve_password"
    original = getattr(LocalLoginBackend, method)

    def resolve(self, h):
        resolved.append(h)
        return original(self, h)

    monkeypatch.setattr(LocalLoginBackend, method, resolve)
    return handle, resolved


def registered(env, monkeypatch, handle, **extras):
    from generic_helpers import registered as plugin
    from gateway.run import _profile_runtime_scope
    from gateway import session_context as sc
    from tools.registry import registry

    with (
        plugin(monkeypatch, env.home, settings=env.settings),
        _profile_runtime_scope(env.home, {}),
    ):
        tokens = sc.set_session_vars(
            platform="telegram",
            user_id="7",
            chat_id="7",
            chat_type="dm",
            session_id=env.browser.sup.task_id,
            session_key="synthetic-login",
            cron_session="",
        )
        try:
            raw = registry.dispatch(
                "secure_login_fill",
                dict(handle=handle, parent=env.parent, origin=env.origin, **extras),
                task_id=env.browser.sup.task_id,
                session_id=env.browser.sup.task_id,
            )
        finally:
            sc.clear_session_vars(tokens)
    assert "Synthetic-Long-Password!" not in raw
    return json.loads(raw)


def test_registered_second_same_origin_old_nonowned(env, monkeypatch):
    handle, resolved = backend(env, monkeypatch)
    assert env.page.evaluate('document.querySelector("#u").value="madeup@example.test"')
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert env.page.evaluate(
        'document.querySelector("#p").value.length>0&&!window.submitted'
    )
    assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    assert not (env.home / "browser_tabs.sqlite").exists()
    import importlib.util

    assert importlib.util.find_spec("tools.browser_tab_lifecycle") is None


@pytest.mark.parametrize("mode", ["login", "totp"])
@pytest.mark.parametrize(
    "topology", ["password_only", "username_first", "nested", "oopif", "open", "closed"]
)
def test_registered_login_topologies(env, monkeypatch, topology, mode):
    if topology in ("nested", "oopif"):
        env.origin = "https://b.test" if topology == "oopif" else "https://a.test"
        env.browser.pages[env.origin + "/leaf"] = (
            "<form><input id=p type=password autocomplete=current-password></form>"
        )
        env.page.evaluate(
            'url=>document.body.innerHTML="<iframe src=\\""+url+"\\"></iframe>"',
            env.origin + "/leaf",
        )
        deadline = time.monotonic() + 10
        while not any(f.url == env.origin + "/leaf" for f in env.page.frames):
            assert time.monotonic() < deadline
            env.page.wait_for_timeout(25)
        env.leaf = next(f for f in env.page.frames if f.url == env.origin + "/leaf")
        env.leaf.wait_for_selector("#p")
    elif topology in ("open", "closed"):
        env.page.evaluate(
            'mode=>{const h=document.body.appendChild(document.createElement("section"));window.fixtureRoot=h.attachShadow({mode});fixtureRoot.append(document.querySelector("form"))}',
            topology,
        )
    else:
        env.page.evaluate('document.querySelector("#u").remove()')
        if topology == "username_first":
            # Username was submitted in a prior document, not forced into this step.
            env.page.evaluate(
                'document.querySelector("form").insertAdjacentHTML("afterbegin","<input type=hidden name=username value=madeup@example.test>")'
            )
    if mode == "totp":
        env.leaf.evaluate(
            "const p=(window.fixtureRoot||document).querySelector('#p');p.type='text';p.autocomplete='one-time-code';p.name='otp'"
        )
    handle, resolved = backend(env, monkeypatch, mode=mode)
    result = registered(env, monkeypatch, handle, mode=mode)
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert env.leaf.evaluate(
        '(window.fixtureRoot||document).querySelector("#p").value.length>0&&!window.submitted'
    )


@pytest.mark.parametrize("mode", ["login", "totp"])
def test_wrong_origin_before_resolver(env, monkeypatch, mode):
    if mode == "totp":
        env.page.evaluate(
            'document.querySelector("form").innerHTML="<input autocomplete=one-time-code>"'
        )
    handle, resolved = backend(env, monkeypatch, origin="https://wrong.test", mode=mode)
    result = registered(env, monkeypatch, handle, mode=mode)
    assert result["status"] == "target_refused", result
    assert not resolved
    assert env.page.evaluate("window.writes===0")


@pytest.mark.parametrize(
    "mutation",
    [
        'const e=document.querySelector("#p");e.replaceWith(e.cloneNode(true))',
        'const e=document.querySelector("#p");document.body.append(e)',
        'const f=document.querySelector("form");f.action="/evil";f.action="/signin"',
        'history.replaceState({},"","/evil");history.replaceState({},"","/login")',
        'document.querySelector("#p").setAttribute("autocomplete","new-password")',
    ],
)
def test_retained_waiting_attacks(env, monkeypatch, mutation):
    handle, resolved = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    try:
        env.page.evaluate("()=>{" + mutation + "}")
        result = lf.fill_login(target, handle, lambda: None)
        assert result["status"] == "target_refused", result
        assert not resolved
        assert env.page.evaluate("window.writes===0")
    finally:
        target.lease.close()


@pytest.mark.parametrize("attack", ["clone", "redirect"])
def test_focus_handler_refuses_before_setter(env, monkeypatch, attack):
    env.page.evaluate(
        'attack=>document.querySelector("#p").addEventListener("focus",()=>{if(attack==="clone"){const e=document.querySelector("#p");e.replaceWith(e.cloneNode(true))}else document.querySelector("#u").focus()},{once:true})',
        attack,
    )
    handle, _ = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result["status"] == "target_refused", result
    assert env.page.evaluate("window.writes===0")


def test_later_focus_switch_no_retarget(env, monkeypatch):
    handle, _ = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    try:
        env.browser.first.bring_to_front()
        result = lf.fill_login(target, handle, lambda: None)
        assert result["status"] in ("target_refused", "filled"), result
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    finally:
        target.lease.close()


def test_registered_origin_bound_totp(env, monkeypatch):
    env.page.evaluate(
        'document.querySelector("form").innerHTML="<input autocomplete=one-time-code>"'
    )
    handle, resolved = backend(env, monkeypatch, mode="totp")
    result = registered(env, monkeypatch, handle, mode="totp")
    assert result["status"] == "filled", result
    assert len(resolved) == 1
    assert env.page.evaluate(
        'document.querySelector("input").value.length===6&&!window.submitted'
    )


@pytest.mark.parametrize("mode", ["login", "totp"])
def test_destination_disagrees_with_handle_even_when_requested_origin_matches(
    env, monkeypatch, mode
):
    handle, resolved = backend(env, monkeypatch, mode=mode)
    env.browser.pages["https://b.test/login"] = (
        "<form><input id=p type=password autocomplete=current-password></form>"
        if mode == "login"
        else "<form><input autocomplete=one-time-code></form>"
    )
    env.page.goto("https://b.test/login")
    # The parent is exactly this B document; the handle/request still name A.
    result = registered(env, monkeypatch, handle, mode=mode)
    assert result["status"] == "target_refused", result
    assert not resolved
    assert env.page.evaluate(
        'Array.from(document.querySelectorAll("input")).every(e=>e.value==="")'
    )
    assert env.browser.first.evaluate('document.querySelector("#p").value===""')


def test_profile_change_before_resolution_on_retained_browser(env, monkeypatch):
    import hermes_constants

    handle, resolved = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    try:
        monkeypatch.setattr(
            hermes_constants, "get_hermes_home", lambda: env.home / "different-profile"
        )
        assert lf.fill_login(target, handle, lambda: None)["status"] == "target_refused"
        assert not resolved
        assert env.page.evaluate("window.writes===0")
    finally:
        target.lease.close()


def test_reconnected_browser_cannot_recapture_retained_login(env, monkeypatch):
    from secure_env_ingress import code_targets

    handle, resolved = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    env.browser.sup.stop()
    env.browser.sup.start()

    def forbidden(*args, **kwargs):
        raise AssertionError("must never capture after binding")

    monkeypatch.setattr(code_targets, "_supervisor", forbidden)
    try:
        assert lf.fill_login(target, handle, lambda: None)["status"] == "target_refused"
        assert not resolved
        assert env.page.evaluate("window.writes===0")
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    finally:
        target.lease.close()
