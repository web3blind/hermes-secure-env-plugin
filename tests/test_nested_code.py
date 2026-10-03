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
    # the same private transport the registered handler uses.

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
            while not port.exists():
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(.05)
            endpoint = 'http://127.0.0.1:' + port.read_text().splitlines()[0]
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
                        sup=sup, parent=parent, endpoint=endpoint)
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


@pytest.mark.parametrize('where', ['root', 'middle', 'leaf'])
@pytest.mark.parametrize('mutation', [
    'const e=document.querySelector("iframe,input");e.replaceWith(e.cloneNode(true))',
    'const e=document.querySelector("iframe,input");e.remove()',
    'const e=document.querySelector("iframe,input");const p=document.createElement("div");document.body.append(p);p.append(e)',
    'const e=document.querySelector("iframe,input");e.setAttribute("title","changed");e.removeAttribute("title")',
    'history.pushState({},"","/changed");history.back()',
    'history.replaceState({},"","/changed");history.replaceState({},"","/root")',
])
def test_mutated_ancestry_never_retargets(nested, where, mutation):
    origin, leaf = setup_chain(nested)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        subject = {'root': nested.page, 'middle': nested.page.frames[1], 'leaf': leaf}[where]
        subject.evaluate('()=>{' + mutation + '}')
        with pytest.raises(Exception):
            codes.assert_target(target)
        with pytest.raises(Exception):
            codes.fill(target, '123456', time.monotonic() + 20)
    finally:
        codes.release(target)


@pytest.mark.parametrize('event', ['focus', 'input'])
@pytest.mark.parametrize('where', ['root', 'middle', 'leaf'])
def test_callback_mutations_stop_later_writes(nested, event, where):
    origin, leaf = setup_chain(nested, split=True)
    leaf.evaluate('([event,where])=>document.querySelector("input").addEventListener(event,()=>{const d=where==="root"?top.document:where==="middle"?parent.document:document;const e=d.querySelector("iframe,input");e.setAttribute("title","changed");e.removeAttribute("title")},{once:true})', [event, where])
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        try:
            assert not codes.fill(target, '123456', time.monotonic() + 20)
        except ValueError:
            pass
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).slice(1).every(e=>e.value==="")')
        if event == 'focus':
            assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


def test_previous_value_tamper_stops_later_write(nested):
    origin, leaf = setup_chain(nested, split=True)
    leaf.evaluate('document.querySelectorAll("input")[1].addEventListener("input",()=>document.querySelector("input").value="x")')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        try:
            assert not codes.fill(target, '123456', time.monotonic() + 20)
        except ValueError:
            pass
        assert leaf.evaluate('document.querySelectorAll("input")[2].value===""')
    finally:
        codes.release(target)


@pytest.mark.parametrize('sites', [('parent.test', 'parent.test'), ('middle.test', 'leaf.test'), ('parent.test', 'leaf.test'), ('middle.test', 'middle.test')])
@pytest.mark.parametrize('split', [False, True])
def test_registered_nested_https(nested, sites, split, tmp_path, monkeypatch, attack=None, focus_exit=None, wrongsite_hook=None):
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
    if focus_exit:
        nested.page.evaluate('document.body.insertAdjacentHTML("beforeend", "<button id=exit>Elsewhere</button>")')
        leaf.evaluate('(event)=>document.querySelector("input").addEventListener(event,()=>top.document.querySelector("#exit").focus(),{once:true})', focus_exit)
    refusal = bool(attack or focus_exit)
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    if wrongsite_hook:
        wrongsite_hook(home)
    factory = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', lambda cfg, h, token: factory(cfg, h, token, trust_roots=root))
    sent = []
    synthetic = 'Q!7&z=' if split else 'Q!7&z=R9'

    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            sent.append(True)
            assert 'authorize' in content and '3-D Secure' in content
            token = urlsplit(content.split('form: ', 1)[1].split(' for ', 1)[0]).fragment
            if attack:
                codes._evaluate(nested.sup, nested.sup._page_session_id, attack)
            status, body = await asyncio.to_thread(post, settings, root, '/submit', {
                'token': token, 'initData': '', 'values': [synthetic]})
            assert status == (409 if refusal else 200)
            assert body == ({'error': 'fill_unconfirmed'} if refusal else {'filled': True})
            return SimpleNamespace(success=True)

    with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM: Adapter()}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', chat_type='group', session_id=nested.sup.task_id, session_key='key', cron_session='')
        try:
            raw = registry.dispatch('browser_vault', {'origin': origin, 'label': 'Synthetic', 'mode': 'code', 'parent': nested.parent}, task_id=nested.sup.task_id, session_id=nested.sup.task_id)
            result = json.loads(raw)
            assert result['status'] == ('unknown' if refusal else 'filled') and len(sent) == 1, result
            assert synthetic not in raw and 'https://' not in raw.replace(origin, '')
        finally:
            sc.clear_session_vars(tokens)
    assert leaf.evaluate('(v)=>Array.from(document.querySelectorAll("input")).map(e=>e.value).join("")===v', synthetic[0] if focus_exit == 'input' else '' if refusal else synthetic)
    assert leaf.evaluate('!window.submitted')
    assert not (home / 'vault').exists()


@pytest.mark.parametrize('attack', [
    'document.querySelector("iframe").setAttribute("title","changed");document.querySelector("iframe").removeAttribute("title")',
    'document.querySelector("iframe").contentDocument.querySelector("iframe").setAttribute("title","changed")',
    'history.replaceState({},"","/changed");history.replaceState({},"","/root")',
])
def test_registered_wait_refuses_without_writes(nested, tmp_path, monkeypatch, attack):
    test_registered_nested_https(nested, ('parent.test', 'parent.test'), True, tmp_path, monkeypatch, attack)


@pytest.mark.parametrize('event', ['focus', 'input'])
def test_registered_focus_exit_is_truthful_unknown(nested, tmp_path, monkeypatch, event):
    test_registered_nested_https(nested, ('parent.test', 'parent.test'), True, tmp_path, monkeypatch, focus_exit=event)


def test_changed_classifier_authority_during_discovery_refuses(nested, monkeypatch):
    from secure_env_ingress import nested_code
    origin, leaf = setup_chain(nested)
    original = nested_code._classified
    def classify(rows):
        if any(row.get('autocomplete') == 'one-time-code' for row in rows):
            leaf.evaluate('const e=document.querySelector("input");e.autocomplete="new-password";e.type="password"')
        return original(rows)
    monkeypatch.setattr(nested_code, '_classified', classify)
    targets = []
    try:
        with pytest.raises(ValueError, match='inspection changed'):
            targets = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)
    finally:
        for target in targets:
            codes.release(target)


@pytest.mark.parametrize('where', ['root', 'middle', 'leaf'])
def test_late_closed_shadow_refuses_without_writes(nested, where):
    origin, leaf = setup_chain(nested)
    subject = {'root': nested.page, 'middle': nested.page.frames[1], 'leaf': leaf}[where]
    subject.evaluate('const host=document.createElement("div");host.id="host";document.body.append(host)')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    try:
        subject.evaluate('document.querySelector("#host").attachShadow({mode:"closed"})')
        with pytest.raises(ValueError):
            codes.fill(target, '123456', time.monotonic() + 10)
        assert leaf.evaluate('document.querySelector("input").value===""')
    finally:
        codes.release(target)


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


@pytest.mark.parametrize('event', ['focus', 'input', 'background'])
def test_actual_leaf_focus_refusal(nested, event):
    origin, leaf = setup_chain(nested, split=True)
    nested.page.evaluate('document.body.insertAdjacentHTML("beforeend", "<button id=exit>Elsewhere</button>")')
    if event != 'background':
        leaf.evaluate('(event)=>document.querySelector("input").addEventListener(event,()=>top.document.querySelector("#exit").focus(),{once:true})', event)
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent)[0]
    background = None
    try:
        if event == 'background':
            background = nested.context.new_page()
            background.goto('https://parent.test/empty')
            for page in (nested.page, background):
                session = nested.context.new_cdp_session(page)
                session.send('Emulation.setFocusEmulationEnabled', {'enabled': False})
                session.detach()
            background.bring_to_front()
            assert not nested.page.evaluate('document.hasFocus()')
        assert not codes.fill(target, '123456', time.monotonic() + 20)
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).slice(1).every(e=>e.value==="")')
        if event != 'input':
            assert leaf.evaluate('document.querySelector("input").value===""')
        else:
            assert leaf.evaluate('document.querySelector("input").value==="1"')
    finally:
        codes.release(target)
        if background:
            background.close()


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


@pytest.mark.parametrize('case', ['wrong-parent', 'wrong-origin', 'opaque', 'shadow', 'ambiguous', 'capacity', 'closed'])
def test_unsupported_targets_fail_safely(nested, case):
    origin, leaf = setup_chain(nested)
    if case == 'opaque':
        nested.pages['https://parent.test/root'] = nested.pages['https://parent.test/root'].replace('<iframe ', '<iframe sandbox="" ')
        nested.page.reload()
    elif case == 'shadow':
        leaf.evaluate('const d=document.createElement("div");document.body.append(d);d.attachShadow({mode:"closed"}).innerHTML="<input autocomplete=one-time-code>"')
    elif case == 'ambiguous':
        leaf.evaluate('document.querySelector("form").append(document.querySelector("input").cloneNode(true))')
    elif case == 'capacity':
        leaf.evaluate('for(let i=0;i<21;i++){const e=document.createElement("iframe");e.src="https://parent.test/empty";document.body.append(e)}')
        nested.page.wait_for_timeout(300)
    elif case == 'closed':
        nested.page.goto('about:blank')
    parent = 'wrong' if case == 'wrong-parent' else nested.parent
    selected_origin = 'https://wrong.test' if case == 'wrong-origin' else origin
    targets = []
    try:
        targets = codes.discover(selected_origin, 'Synthetic', nested.sup.task_id, parent=parent)
        assert targets == []
    except (ValueError, RuntimeError):
        pass
    finally:
        for target in targets:
            codes.release(target)
