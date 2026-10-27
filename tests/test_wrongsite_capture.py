"""Stock Browser Harness selection → owner-free exact parent → registered tools."""
import asyncio
from contextlib import contextmanager
import json
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import yaml

from test_nested_code import nested as chromium_fixture
from secure_env_ingress import code_targets as codes, payment_fill as pf

nested = chromium_fixture


@contextmanager
def captured_parent(nested, tmp_path, monkeypatch, home, html):
    from gateway.run import _profile_runtime_scope
    from hermes_state import SessionDB
    from hermes_constants import get_hermes_home
    assert importlib.util.find_spec("tools.browser_tab_lifecycle") is None
    from tools import browser_use_cli as host
    unrelated = tmp_path / 'process-home'
    unrelated.mkdir(exist_ok=True)
    monkeypatch.setenv('HERMES_HOME', str(unrelated))
    task = nested.sup.task_id
    db = SessionDB(db_path=home / 'state.db')
    db.create_session(task, 'telegram')
    db.close()
    (home / 'config.yaml').write_text(yaml.safe_dump({'browser': {'tab_cleanup_enabled': False}}))
    private = Path(tempfile.mkdtemp(prefix='bh-', dir=os.environ['TMPDIR']))
    env = dict(PATH=os.environ['PATH'], HOME=str(private), LANG='C.UTF-8',
               BU_CDP_WS=nested.sup.cdp_url, BH_HOME=str(private),
               BH_RUNTIME_DIR=str(private / 'ipc'), BH_TMP_DIR=str(private / 'tmp'),
               BH_AGENT_WORKSPACE=str(private / 'workspace'), BH_RECORD='0',
               BH_TAB_MARKER='0', DO_NOT_TRACK='1', ANONYMIZED_TELEMETRY='false',
               TMPDIR=str(private))
    assert host._find_cli(), 'stock Browser Harness dependency must be installed'
    monkeypatch.setattr(host, '_base_subprocess_env', lambda: env.copy())
    page, other, sibling, daemon = None, None, None, None
    default = nested.context.browser.contexts[0]
    try:
        with _profile_runtime_scope(home, {}):
            assert get_hermes_home() == home and home != unrelated
            request_code = "from browser_harness import helpers; print('CAPTURE_PID=' + str(helpers._send({'meta': 'ping'})['pid'])); print('CAPTURE_TARGET=' + helpers._send({'meta': 'current_tab'})['targetId'])"
            # The page predates this Harness call; no creator/owner authority.
            existing = default.new_page()
            session = default.new_cdp_session(existing)
            existing_id = session.send("Target.getTargetInfo")["targetInfo"]["targetId"]
            session.detach()
            request_code = "switch_tab(" + repr(existing_id) + ")\n" + request_code
            result = json.loads(host.browser_exec(request_code, task_id=task, timeout_s=30))
            assert result['success'], json.dumps(result)
            pid = int(next(line.split('=', 1)[1] for line in result['output'].splitlines() if line.startswith('CAPTURE_PID=')))
            daemon = (pid, (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            parent = next(line.split('=', 1)[1] for line in result['output'].splitlines() if line.startswith('CAPTURE_TARGET='))
            assert parent == existing_id
            assert not (home / 'browser_tabs.sqlite').exists()
            assert not (unrelated / 'browser_tabs.sqlite').exists()
            deadline = time.monotonic() + 3
            while page is None and time.monotonic() < deadline:
                nested.page.wait_for_timeout(50)  # Drain real target-created events.
                for context in nested.context.browser.contexts:
                    for candidate in context.pages:
                        session = context.new_cdp_session(candidate)
                        try:
                            target_id = session.send('Target.getTargetInfo')['targetInfo']['targetId']
                        finally:
                            session.detach()
                        if target_id == parent:
                            page, default = candidate, context
                            break
                    if page:
                        break
            assert page is not None, 'captured target not exposed by disposable browser'
            default.route('https://capture.test/**', lambda route: route.fulfill(body=html.get(route.request.url, ''), content_type='text/html'))
            page.goto('https://capture.test/root')
            page.frames[-1].wait_for_selector('input')
            selected = json.loads(host.browser_exec("from browser_harness import helpers; print('CAPTURE_TARGET=' + helpers._send({'meta': 'current_tab'})['targetId'])", task_id=task, timeout_s=30))
            assert selected['success'] and 'CAPTURE_TARGET=' + parent in selected['output']
            sibling = default.new_page()
            sibling.goto('https://capture.test/root')
            sibling.frames[-1].wait_for_selector('input')
            other = nested.context.new_page()
            other.goto('https://other.test/root')
            assert nested.sup.focus_page('https://other.test')['ok']
            previous = nested.sup._page_session_id
            page.bring_to_front()
            yield SimpleNamespace(parent=parent, page=page, leaf=page.frames[-1], previous=previous, unrelated=unrelated)
            assert sibling.frames[-1].evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
            assert not (home / 'browser_tabs.sqlite').exists()
    finally:
        if sibling:
            sibling.close()
        if other:
            other.close()
        if page:
            page.close()
        default.unroute('https://capture.test/**')
        if daemon:
            pid, start = daemon
            proc = Path('/proc') / str(pid)
            try:
                if proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == str(start):
                    os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, FileNotFoundError):
                pass
        shutil.rmtree(private, ignore_errors=True)


@pytest.mark.parametrize('choice', ['once', 'deny'])
def test_captured_registered_payment(nested, tmp_path, monkeypatch, choice):
    from agent.vault_store import VaultStore
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime
    from payment_consent_helpers import payment_consent
    from gateway.run import _profile_runtime_scope
    from tools.registry import registry
    sample, settings, home, _ = make_runtime(tmp_path, mini=False)
    sample.close()
    html = {'https://capture.test/root': '<iframe src="https://capture.test/pay"></iframe>',
            'https://capture.test/pay': '<form onsubmit="window.submitted=true;return false"><input autocomplete="cc-name"><input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY"><input autocomplete="cc-csc"></form>'}
    with captured_parent(nested, tmp_path, monkeypatch, home, html) as captured:
        secret = dict(card_number='4242424242424242', cardholder_name='Synthetic Holder', exp_month='12', exp_year='2031', cvc='123')
        handle = VaultStore(home / 'vault').add_item('payment', 'Synthetic card', secret, origin='https://capture.test').id
        with registered(monkeypatch, home, settings=settings), _profile_runtime_scope(home, {}):
            with payment_consent(choice, session=nested.sup.task_id) as seen:
                raw = registry.dispatch('secure_payment_fill', dict(handle=handle, parent=captured.parent, origin='https://capture.test'), task_id=nested.sup.task_id, session_id=nested.sup.task_id)
        result = json.loads(raw)
        assert result['status'] == ('filled' if choice == 'once' else 'payment_declined'), result
        assert len(seen) == 1 and secret['card_number'] not in raw + json.dumps(seen)
        assert captured.leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!!e.value)') == (choice == 'once')
        assert captured.leaf.evaluate('!window.submitted')
        assert nested.sup._page_session_id == captured.previous
        assert not (captured.unrelated / 'vault').exists()


def test_captured_registered_nested_https(nested, tmp_path, monkeypatch):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime, post
    from test_tool_https_e2e import running_gateway_loop
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from hermes_constants import get_hermes_home
    from tools.registry import registry
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    html = {'https://capture.test/root': '<iframe src="https://capture.test/middle"></iframe>',
            'https://capture.test/middle': '<iframe src="https://capture.test/code"></iframe>',
            'https://capture.test/code': '<form onsubmit="window.submitted=true;return false"><input autocomplete="one-time-code"></form>'}
    with captured_parent(nested, tmp_path, monkeypatch, home, html) as captured:
        sent = []
        class Adapter:
            async def send(self, chat_id, content, metadata=None):
                sent.append(True)
                token = urlsplit(content.split('form: ', 1)[1].split(' for ', 1)[0]).fragment
                status, body = await asyncio.to_thread(post, settings, root, '/submit', {'token': token, 'initData': '', 'values': ['Q!7&z=R9']})
                assert status == 200 and body == {'filled': True}
                return SimpleNamespace(success=True)
        with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings, trust_roots=root) as (_, gateway), _profile_runtime_scope(home, {}):
            gateway._gateway_loop = loop
            gateway.adapters = {Platform.TELEGRAM: Adapter()}
            event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'), text='synthetic')
            invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
            tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', chat_type='group', session_id=nested.sup.task_id, session_key='key', cron_session='')
            try:
                assert get_hermes_home() == home and os.environ['HERMES_HOME'] != str(home)
                raw = registry.dispatch('secure_env_vault', dict(mode='code', origin='https://capture.test', label='Synthetic', parent=captured.parent), task_id=nested.sup.task_id, session_id=nested.sup.task_id)
                assert json.loads(raw)['status'] == 'filled', raw
                assert len(sent) == 1 and 'Q!7&z=R9' not in raw
            finally:
                sc.clear_session_vars(tokens)
        assert captured.leaf.evaluate('document.querySelector("input").value === "Q!7&z=R9"')
        assert captured.leaf.evaluate('!window.submitted')
        assert nested.sup._page_session_id == captured.previous
        assert not (home / 'vault').exists() and not (captured.unrelated / 'vault').exists()


@pytest.mark.parametrize('bad', ['missing-parent', 'closed-parent', 'wrong-origin'])
@pytest.mark.parametrize('adapter', ['payment', 'code'])
def test_real_capture_negative_destination(nested, tmp_path, monkeypatch, bad, adapter):
    from gateway.run import _profile_runtime_scope
    from secure_env_ingress.bound_cdp import BoundCDP
    home = tmp_path / 'capture-home'
    home.mkdir()
    html = {'https://capture.test/root': '<iframe src="https://capture.test/code"></iframe>',
            'https://capture.test/code': '<form><input autocomplete="one-time-code"></form>'}
    if adapter == 'payment':
        html['https://capture.test/code'] = ('<form><input autocomplete="cc-name">'
            '<input autocomplete="cc-number"><input autocomplete="cc-exp" placeholder="MM/YY">'
            '<input autocomplete="cc-csc"></form>')
    with captured_parent(nested, tmp_path, monkeypatch, home, html) as captured:
        target = None if bad == 'missing-parent' else captured.parent
        if bad == 'closed-parent':
            captured.page.close()
        origin = 'https://wrong.test' if bad == 'wrong-origin' else 'https://capture.test'
        sent = []
        original = BoundCDP.call
        def observe(self, method, *args, **kwargs):
            sent.append(method)
            return original(self, method, *args, **kwargs)
        monkeypatch.setattr(BoundCDP, 'call', observe)
        def discover():
            if adapter == 'code':
                return codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=target)
            return pf.discover(nested.sup.task_id, target, origin)
        with _profile_runtime_scope(home, {}):
            if bad == 'wrong-origin':
                # Prove an actual candidate exists before testing the origin fence.
                if adapter == 'code':
                    valid = codes.discover('https://capture.test', 'Synthetic', nested.sup.task_id, parent=target)
                    release = codes.release
                else:
                    valid = pf.discover(nested.sup.task_id, target, 'https://capture.test')
                    release = pf.release
                try:
                    assert len(valid) == 1
                finally:
                    for candidate in valid:
                        release(candidate)
                assert not discover()  # A complete census finds no authorized destination.
            else:
                with pytest.raises(ValueError):
                    discover()
        if bad == 'missing-parent':
            assert 'Target.attachToTarget' not in sent
        assert nested.sup._page_session_id == captured.previous
        assert not (home / 'browser_tabs.sqlite').exists()


@pytest.mark.parametrize('change', ['profile', 'reconnect', 'navigation', 'replacement'])
def test_harness_retained_code_lifecycle(nested, tmp_path, monkeypatch, change):
    from gateway.run import _profile_runtime_scope
    home = tmp_path / 'capture-home'
    home.mkdir()
    html = {'https://capture.test/root': '<iframe src="https://capture.test/code"></iframe>',
            'https://capture.test/code': '<form><input autocomplete="one-time-code"></form>'}
    with captured_parent(nested, tmp_path, monkeypatch, home, html) as captured:
        targets = codes.discover('https://capture.test', 'Synthetic', nested.sup.task_id, parent=captured.parent)
        assert len(targets) == 1
        try:
            codes.assert_target(targets[0])
            if change == 'profile':
                foreign = tmp_path / 'foreign-profile'
                foreign.mkdir()
                with _profile_runtime_scope(foreign, {}), pytest.raises(ValueError):
                    codes.assert_target(targets[0])
            else:
                if change == 'reconnect':
                    nested.sup.stop()
                    nested.sup.start()
                elif change == 'navigation':
                    captured.page.goto('https://capture.test/changed')
                else:
                    captured.leaf.evaluate('const e=document.querySelector("input");e.replaceWith(e.cloneNode(true))')
                with pytest.raises(ValueError):
                    codes.assert_target(targets[0])
            if change == 'profile':
                with _profile_runtime_scope(foreign, {}), pytest.raises(ValueError, match='parent connection changed or discovery cancelled'):
                    codes.fill(targets[0], '654321', time.monotonic() + 10)
            else:
                reason = 'invalid code fields' if change == 'replacement' else 'parent connection changed or command refused'
                with pytest.raises(ValueError, match=reason):
                    codes.fill(targets[0], '654321', time.monotonic() + 10)
            if change != 'navigation':
                assert captured.leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>!e.value)')
        finally:
            for target in targets:
                codes.release(target)
