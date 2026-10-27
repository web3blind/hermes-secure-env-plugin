"""Actual Chromium retained writes, paused at the public captured send seam."""
import threading
import time

import pytest
from test_retained_login_browser import browser as _browser, env as _env, backend
from secure_env_ingress import login_fill as lf
from secure_env_ingress.bound_cdp import acquisition_scope

browser = _browser
env = _env


@pytest.mark.parametrize('change', ['cancel', 'human_epoch', 'expiry', 'profile'])
def test_queued_login_write_never_dispatches_after_admission_change(env, monkeypatch, change):
    from tools import browser_vault_tool
    from tools.bot_desktop import lease
    monkeypatch.setattr(browser_vault_tool, '_bot_desktop_browser_session', lambda task: True)
    handle, resolved = backend(env, monkeypatch)
    cancelled = threading.Event()
    with acquisition_scope(cancelled):
        target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    if change == 'expiry':
        from dataclasses import replace
        target = replace(target, expires=time.monotonic() + 5)
    raw = target.supervisor.raw
    original = raw.call
    paused, resume, queued = threading.Event(), threading.Event(), threading.Event()
    changers = []
    def call(method, params=None, *, session_id=None, timeout=10.0, before_send=None):
        if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == 'function(v){return this.write(v)}':
            def block_loop():
                paused.set()
                resume.wait(6)
            env.browser.sup._loop.call_soon_threadsafe(block_loop)
            assert paused.wait(2)
            queued.set()
            def change_state():
                try:
                    time.sleep(max(.08, target.expires - time.monotonic() + .02) if change == 'expiry' else .08)
                    if change == 'cancel':
                        cancelled.set()
                    elif change == 'human_epoch':
                        lease.acquire('synthetic-viewer', profile_key=str(env.home))
                        lease.release('synthetic-viewer', profile_key=str(env.home))
                    elif change == 'profile':
                        import hermes_constants
                        monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: env.home / 'different-profile')
                finally:
                    resume.set()
            worker = threading.Thread(target=change_state)
            changers.append(worker)
            worker.start()
        return original(method, params, session_id=session_id, timeout=timeout, before_send=before_send)
    monkeypatch.setattr(raw, 'call', call)
    try:
        result = lf.fill_login(target, handle, lambda: None)
        assert queued.is_set(), result
        assert result['success'] is False
        assert len(resolved) == 1
        assert env.page.evaluate('window.writes===0&&document.querySelector("#p").value===""')
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    finally:
        resume.set()
        for worker in changers:
            worker.join(6)
        target.lease.close()


def test_retained_iframe_replacement_before_resolver(env, monkeypatch):
    env.browser.pages['https://a.test/leaf'] = '<form><input id=p type=password autocomplete=current-password></form>'
    env.page.evaluate('document.body.innerHTML="<iframe src=/leaf></iframe>"')
    env.page.frames[-1].wait_for_selector('#p')
    handle, resolved = backend(env, monkeypatch)
    target = lf.discover(env.browser.sup.task_id, env.parent, env.origin, lambda: None)
    try:
        env.page.evaluate('const f=document.querySelector("iframe");f.replaceWith(f.cloneNode(true))')
        assert lf.fill_login(target, handle, lambda: None)['success'] is False
        assert not resolved
        assert env.browser.first.evaluate('document.querySelector("#p").value===""')
    finally:
        target.lease.close()
