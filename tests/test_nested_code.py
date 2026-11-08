"""Nested OTP transport checks against disposable Chromium, never live CDP."""
import json
import time
import urllib.request

import pytest

from secure_env_ingress import code_targets as codes

@pytest.fixture(scope='module')
def nested():
    from tools.browser_supervisor import CDPSupervisor, SUPERVISOR_REGISTRY
    from pathlib import Path
    assert Path(codes.__file__).resolve().parents[1] == Path(__file__).resolve().parents[1]
    # Playwright owns this fresh process. Its browser-level CDP session exposes
    # the host's real public captured-CDP seam used by registered handlers.

    from types import SimpleNamespace
    # Use a separate websocket-enabled isolated process, not the user's browser.
    import subprocess
    import tempfile
    import os
    with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'), ignore_cleanup_errors=True) as directory:
        proc = subprocess.Popen(['chromium', '--headless=new', '--no-sandbox',
            '--remote-debugging-port=0', '--user-data-dir=' + directory, 'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            port = Path(directory) / 'DevToolsActivePort'
            deadline = time.monotonic() + 20
            # Chromium creates DevToolsActivePort before finishing its contents.
            # Retain the same startup budget, but wait for both complete lines.
            lines = []
            while len(lines) < 2 or not lines[0].isdigit():
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(.05)
                lines = port.read_text().splitlines() if port.exists() else []
            endpoint = 'http://127.0.0.1:' + lines[0]
            with urllib.request.urlopen(endpoint + '/json/version') as response:
                ws = json.load(response)['webSocketDebuggerUrl']
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.connect_over_cdp(endpoint)
                context = browser.new_context(ignore_https_errors=True)
                pages = {'https://parent.test/root': '<iframe src="https://parent.test/middle"></iframe>',
                    'https://parent.test/middle': '<iframe src="https://parent.test/leaf"></iframe>',
                    'https://parent.test/leaf': '<form><label>Verification code<input autocomplete="one-time-code"></label></form>'}
                context.route('**/*', lambda r: r.fulfill(body=pages.get(r.request.url, ''), content_type='text/html'))
                page = context.new_page()
                page.goto('https://parent.test/root')
                page.frames[-1].wait_for_selector('input')
                sup = CDPSupervisor('nested-fixture', ws)
                sup.start()
                with SUPERVISOR_REGISTRY._lock:
                    SUPERVISOR_REGISTRY._by_task[sup.task_id] = sup
                sup.focus_page('https://parent.test')
                session = context.new_cdp_session(page)
                parent = session.send('Target.getTargetInfo')['targetInfo']['targetId']
                session.detach()
                try:
                    yield SimpleNamespace(page=page, context=context, pages=pages,
                        sup=sup, parent=parent, endpoint=endpoint,
                        capture=lambda: SUPERVISOR_REGISTRY.capture(sup.task_id))
                finally:

                    sup.stop()
                    with SUPERVISOR_REGISTRY._lock:
                        SUPERVISOR_REGISTRY._by_task.pop(sup.task_id, None)
                    context.close()
                    browser.close()
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def test_nested_single_transport(nested):
    origin, leaf = setup_chain(nested)
    targets = codes.discover(origin, 'Synthetic code', nested.sup.task_id, parent=nested.parent)
    assert len(targets) == 1
    target = targets[0]
    try:
        codes.assert_target(target)
        assert codes.fill(target, 'Q!7&z=R9', time.monotonic() + 20)
        assert leaf.evaluate('document.querySelector("input").value === "Q!7&z=R9"')
    finally:
        if hasattr(codes, 'release'):
            codes.release(target)


def setup_chain(nested, sites=('parent.test', 'parent.test'), split=False):
    middle, leaf = sites
    origin = 'https://' + leaf
    nested.pages['https://parent.test/root'] = '<iframe src="https://' + middle + '/middle"></iframe>'
    nested.pages['https://' + middle + '/middle'] = '<iframe src="' + origin + '/leaf"></iframe>'
    controls = '<input autocomplete="one-time-code" maxlength="1">' * 6 if split else '<input autocomplete="one-time-code">'
    nested.pages[origin + '/leaf'] = '<form onsubmit="window.submitted=true;return false">' + controls + '</form>'
    nested.page.close()
    nested.page = nested.context.new_page()
    nested.page.goto('https://parent.test/root', wait_until='domcontentloaded')
    deadline = time.monotonic() + 10
    while not any(f.url == origin + '/leaf' for f in nested.page.frames):
        assert time.monotonic() < deadline, 'synthetic leaf failed to load'
        nested.page.wait_for_timeout(50)
    frame = next(f for f in nested.page.frames if f.url == origin + '/leaf')
    frame.wait_for_selector('input')
    session = nested.context.new_cdp_session(nested.page)
    nested.parent = session.send('Target.getTargetInfo')['targetInfo']['targetId']
    session.detach()
    assert nested.sup.focus_page('https://parent.test')['ok']
    return origin, frame


@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test'), ('parent.test', 'leaf.test'), ('middle.test', 'middle.test')])
@pytest.mark.parametrize('split', [False, True])
def test_same_oopif_mixed_single_split(nested, sites, split):
    origin, leaf = setup_chain(nested, sites, split)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        assert len(target.ancestry) == 2
        assert codes.fill(target, 'Q!7&z=' if split else 'Q!7&z=R9', time.monotonic() + 20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).map(e=>e.value).join("") === ' + json.dumps('Q!7&z=' if split else 'Q!7&z=R9'))
        assert leaf.evaluate('!window.submitted')
    finally:
        codes.release(target)








@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test'), ('parent.test', 'leaf.test'), ('middle.test', 'middle.test')])
@pytest.mark.parametrize('split', [False, True])
def test_registered_nested_https(nested, sites, split, tmp_path, monkeypatch, attack=None, focus_exit=None, wrongsite_hook=None, field_selector=None, markup=None, shadow_mode=None, setup_hook=None, synthetic_code=None, completion_check=None, expect_unknown=False):
    import asyncio
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime, post
    from test_tool_https_e2e import running_gateway_loop
    from secure_env_ingress import runtime as runtime_module
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry

    origin, leaf = setup_chain(nested, sites, split)
    if markup is not None:
        leaf.evaluate('(markup) => {document.body.innerHTML=markup}', markup)
    if setup_hook is not None:
        setup_hook(leaf)
    if shadow_mode is not None:
        leaf.evaluate('(mode)=>{const r=document.body.appendChild(document.createElement("div")).attachShadow({mode});r.innerHTML=document.querySelector("form").outerHTML;document.querySelector("form").remove();window.fixtureRoot=r}', shadow_mode)
    if focus_exit:
        nested.page.evaluate('document.body.insertAdjacentHTML("beforeend", "<button id=exit>Elsewhere</button>")')
        leaf.evaluate('(event)=>document.querySelector("input").addEventListener(event,()=>top.document.querySelector("#exit").focus(),{once:true})', focus_exit)
    refusal = bool(attack or focus_exit or expect_unknown)
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    if wrongsite_hook:
        wrongsite_hook(home)
    factory = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', lambda cfg, h, token: factory(cfg, h, token, trust_roots=root))
    sent = []
    synthetic = synthetic_code or ('Q!7&z=' if split else 'Q!7&z=R9')

    pending_submissions = []
    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            # Delivery acknowledgement precedes the human HTTPS submission.
            pending_submissions.append(asyncio.create_task(self.submit(chat_id, content, metadata)))
            return SimpleNamespace(success=True)

        async def submit(self, chat_id, content, metadata=None):
            sent.append(True)
            assert 'authorize' in content and '3-D Secure' in content
            token = urlsplit(content.split('form: ', 1)[1].split(' for ', 1)[0]).fragment
            if attack:
                codes._evaluate(nested.capture(), nested.sup._page_session_id, attack)
            status, body = await asyncio.to_thread(post, settings, root, '/submit', {
                'token': token, 'initData': '', 'values': [synthetic]}, timeout=120)
            # Guarded split/OOPIF/exact-parent CDP fills can exceed three
            # seconds. This is only the fixture client's HTTPS read timeout;
            # production target/authorization TTL and cancellation are unchanged.
            assert status == (409 if refusal else 200)
            assert body == ({'error': 'fill_unconfirmed'} if refusal else {'filled': True})
            return SimpleNamespace(success=True)

    async def drained_submissions():
        await asyncio.gather(*pending_submissions)

    with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM: Adapter()}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', chat_type='group', session_id=nested.sup.task_id, session_key='key', cron_session='')
        try:
            raw = registry.dispatch('secure_env_vault', {'origin': origin, 'label': 'Synthetic', 'mode': 'code', 'parent': nested.parent, **({'field_selector': field_selector} if field_selector is not None else {})}, task_id=nested.sup.task_id, session_id=nested.sup.task_id)
            asyncio.run_coroutine_threadsafe(drained_submissions(), loop).result(timeout=180)
            result = json.loads(raw)
            assert result['status'] == ('unknown' if refusal else 'filled') and len(sent) == 1, result
            assert synthetic not in raw and 'https://' not in raw.replace(origin, '')
        finally:
            sc.clear_session_vars(tokens)
    if completion_check is not None:
        completion_check(leaf)
    else:
        assert leaf.evaluate('(v)=>Array.from((window.fixtureRoot||document).querySelectorAll("input")).map(e=>e.value).join("")===v', synthetic[0] if focus_exit == 'input' else '' if refusal else synthetic)
    assert leaf.evaluate('!window.submitted')
    assert not (home / 'vault').exists()










def test_duplicate_concurrent_release_preserves_other_candidate():
    import threading
    from types import SimpleNamespace
    from secure_env_ingress.nested_code import _Lease, release
    class DelayedSet(set):
        def __contains__(self, item):
            present = super().__contains__(item)
            time.sleep(.01)
            return present
    lease = _Lease(None)
    lease.refs = 2
    lease.released = DelayedSet()
    target = SimpleNamespace(lease=lease, leaf_guard='first')
    threads = [threading.Thread(target=release, args=(target,)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()
    assert lease.refs == 1 and not lease.closed
    release(SimpleNamespace(lease=lease, leaf_guard='second'))
    assert lease.closed




def test_shared_siblings_retire_private_guard_and_expire_automatically(nested):
    from secure_env_ingress import nested_code as n
    origin, leaf = setup_chain(nested, ('middle.test', 'leaf.test'))
    leaf.evaluate('document.body.append(document.querySelector("form").cloneNode(true))')
    picker = codes.CodeSelection()
    picker.ttl_seconds = 4
    try:
        _, response = picker.choose(('scope',), origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
        token, sibling_token = [x['selection'] for x in response['candidates']]
        sibling = picker._entries[sibling_token][2]
        selected, _ = picker.choose(('scope',), origin, 'Synthetic', nested.sup.task_id, token, nested.parent)
        assert codes.fill(selected, '123456', time.monotonic() + 20)
        lease = selected.lease
        assert lease.sessions  # OOPIF attachments really owned by this batch.
        codes.release(selected)
        assert lease.refs == 1 and not lease.closed
        assert (selected.leaf_sid, selected.leaf_guard) not in lease.objects
        codes.assert_target(sibling)
        assert n._invoke(sibling.supervisor, sibling.leaf_sid, sibling.leaf_guard, 'function(){return this.valid()}').get('value') is True
        deadline = time.monotonic() + 6
        while not lease.closed and time.monotonic() < deadline:
            time.sleep(.02)
        assert lease.closed and not lease.objects and not lease.sessions and not picker._entries
    finally:
        picker.close()


def test_expired_fill_performs_no_writes(nested):
    origin, leaf = setup_chain(nested, split=True)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        assert not codes.fill(target, '123456', time.monotonic() - 1)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)


def test_selection_parent_origin_scope_expiry_and_reuse(nested, monkeypatch):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.append(document.querySelector("form").cloneNode(true))')
    picker = codes.CodeSelection()
    try:
        _, choices = picker.choose(('home', 'owner', 'chat'), origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
        assert len(choices['candidates']) == 2
        assert 'href' not in json.dumps(choices) and '/leaf' not in json.dumps(choices)
        token = choices['candidates'][0]['selection']
        for scope, url, label, task, parent in [
            (('other',), origin, 'Synthetic', nested.sup.task_id, nested.parent),
            (('home','owner','chat'), 'https://wrong.test', 'Synthetic', nested.sup.task_id, nested.parent),
            (('home','owner','chat'), origin, 'Other', nested.sup.task_id, nested.parent),
            (('home','owner','chat'), origin, 'Synthetic', 'other-task', nested.parent),
            (('home','owner','chat'), origin, 'Synthetic', nested.sup.task_id, 'other-parent'),
            (('home','owner','chat'), origin, 'Synthetic', nested.sup.task_id, None),
        ]:
            with pytest.raises(ValueError):
                picker.choose(scope, url, label, task, token, parent)
        target, _ = picker.choose(('home','owner','chat'), origin, 'Synthetic', nested.sup.task_id, token, nested.parent)
        codes.release(target)
        with pytest.raises(ValueError):
            picker.choose(('home','owner','chat'), origin, 'Synthetic', nested.sup.task_id, token, nested.parent)
        token = choices['candidates'][1]['selection']
        now = time.monotonic()
        monkeypatch.setattr(codes.time, 'monotonic', lambda: now + 121)
        with pytest.raises(ValueError):
            picker.choose(('home','owner','chat'), origin, 'Synthetic', nested.sup.task_id, token, nested.parent)
    finally:
        picker.close()
