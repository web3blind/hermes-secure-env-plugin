"""Real host Browser Use capture; no manufactured ownership proof."""
import asyncio
from contextlib import contextmanager
import json
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


def installed_cli():
    found = shutil.which('browser-use')
    if found:
        return found
    archive = Path.home() / '.cache/uv/archive-v0'
    cached = [p for p in archive.glob('*/bin/browser-use')
              if (p.parent.parent / 'lib/python3.11/site-packages/browser_harness/helpers.py').is_file()]
    if not cached:
        pytest.skip('Browser Use CLI unavailable; no install permitted')
    return str(max(cached, key=lambda p: p.stat().st_mtime))


@contextmanager
def captured_parent(nested, tmp_path, monkeypatch, home, html, *, capture=True):
    from gateway.run import _profile_runtime_scope
    from hermes_state import SessionDB
    from hermes_constants import get_hermes_home
    from tools import browser_use_cli as host, browser_tab_lifecycle as life
    from tools.browser_tab_lifecycle import readonly
    unrelated = tmp_path / 'process-home'
    unrelated.mkdir(exist_ok=True)
    monkeypatch.setenv('HERMES_HOME', str(unrelated))
    task = nested.sup.task_id
    db = SessionDB(db_path=home / 'state.db')
    db.create_session(task, 'telegram')
    db.close()
    (home / 'config.yaml').write_text(yaml.safe_dump({'browser': {'tab_cleanup_enabled': capture}}))
    private = Path(tempfile.mkdtemp(prefix='bh-', dir=os.environ['TMPDIR']))
    env = dict(PATH=os.environ['PATH'], HOME=str(private), LANG='C.UTF-8',
               BU_CDP_WS=nested.sup.cdp_url, BH_HOME=str(private),
               BH_RUNTIME_DIR=str(private / 'ipc'), BH_TMP_DIR=str(private / 'tmp'),
               BH_AGENT_WORKSPACE=str(private / 'workspace'), BH_RECORD='0',
               BH_TAB_MARKER='0', DO_NOT_TRACK='1', ANONYMIZED_TELEMETRY='false',
               TMPDIR=str(private))
    monkeypatch.setattr(host, '_find_cli', lambda: [installed_cli()])
    monkeypatch.setattr(host, '_base_subprocess_env', lambda: env.copy())
    page, other, daemon = None, None, None
    default = nested.context.browser.contexts[0]
    try:
        with _profile_runtime_scope(home, {}):
            assert get_hermes_home() == home and home != unrelated
            request_code = "from browser_harness import helpers; print('CAPTURE_PID=' + str(helpers._send({'meta': 'ping'})['pid'])); print('CAPTURE_TARGET=' + helpers._send({'meta': 'current_tab'})['targetId'])"
            if not capture:
                request_code = "switch_tab(cdp('Target.createTarget', url='about:blank')['targetId'])\n" + request_code
            result = json.loads(host.browser_exec(request_code, task_id=task, session_id=task, timeout_s=30))
            assert result['success'], json.dumps(result)
            pid = int(next(line.split('=', 1)[1] for line in result['output'].splitlines() if line.startswith('CAPTURE_PID=')))
            daemon = (pid, (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            parent = next(line.split('=', 1)[1] for line in result['output'].splitlines() if line.startswith('CAPTURE_TARGET='))
            if capture:
                with readonly(home / 'browser_tabs.sqlite') as db:
                    row = db.execute('SELECT t.*, c.state,c.inflight,c.daemon_pid,c.daemon_start FROM targets t JOIN calls c ON c.token=t.call_token WHERE t.target=?', (parent,)).fetchone()
                    assert row and row['browser'] == nested.sup.cdp_url, {'parent': parent, 'rows': [dict(r) for r in db.execute('SELECT target,browser,owner,generation FROM targets')]}
                    assert row['owner'] == 'session:' + task and row['generation'] == task
                    assert row['state'] == 'drained' and row['inflight'] == 0
                    assert (row['daemon_pid'], row['daemon_start']) == daemon and not row['pending_close']
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
            if capture:
                selected = json.loads(host.browser_exec("from browser_harness import helpers; print('CAPTURE_TARGET=' + helpers._send({'meta': 'current_tab'})['targetId'])", task_id=task, session_id=task, timeout_s=30))
                assert selected['success'] and 'CAPTURE_TARGET=' + parent in selected['output']
            other = nested.context.new_page()
            other.goto('https://other.test/root')
            assert nested.sup.focus_page('https://other.test')['ok']
            previous = nested.sup._page_session_id
            page.bring_to_front()
            yield SimpleNamespace(parent=parent, page=page, leaf=page.frames[-1], previous=previous, unrelated=unrelated)
    finally:
        if other:
            other.close()
        if page:
            page.close()
        default.unroute('https://capture.test/**')
        handle = life._handles.pop(str(home.resolve()), None)
        if handle:
            handle.cancel()
        if daemon:
            pid, start = daemon
            proc = Path('/proc') / str(pid)
            try:
                if proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19] == str(start):
                    os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
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
                raw = registry.dispatch('browser_vault', dict(mode='code', origin='https://capture.test', label='Synthetic', parent=captured.parent), task_id=nested.sup.task_id, session_id=nested.sup.task_id)
                assert json.loads(raw)['status'] == 'filled', raw
                assert len(sent) == 1 and 'Q!7&z=R9' not in raw
            finally:
                sc.clear_session_vars(tokens)
        assert captured.leaf.evaluate('document.querySelector("input").value === "Q!7&z=R9"')
        assert captured.leaf.evaluate('!window.submitted')
        assert nested.sup._page_session_id == captured.previous
        assert not (home / 'vault').exists() and not (captured.unrelated / 'vault').exists()


@pytest.mark.parametrize('bad', ['missing-capture', 'unrecorded', 'foreign-profile'])
@pytest.mark.parametrize('adapter', ['payment', 'code'])
def test_real_capture_negative_authority(nested, tmp_path, monkeypatch, bad, adapter):
    from gateway.run import _profile_runtime_scope
    from hermes_state import SessionDB
    from secure_env_ingress.bound_cdp import BoundCDP
    home = tmp_path / 'capture-home'
    home.mkdir()
    html = {'https://capture.test/root': '<iframe src="https://capture.test/code"></iframe>',
            'https://capture.test/code': '<form><input autocomplete="one-time-code"></form>'}
    with captured_parent(nested, tmp_path, monkeypatch, home, html, capture=bad != 'missing-capture') as captured:
        target, unknown = captured.parent, None
        selected_home = home
        if bad == 'foreign-profile':
            selected_home = tmp_path / 'foreign'
            selected_home.mkdir()
            db = SessionDB(db_path=selected_home / 'state.db')
            db.create_session(nested.sup.task_id, 'telegram')
            db.close()
        elif bad == 'unrecorded':
            unknown = nested.context.new_page()
            unknown.goto('https://unrecorded.test/root')
            session = nested.context.new_cdp_session(unknown)
            target = session.send('Target.getTargetInfo')['targetInfo']['targetId']
            session.detach()
        sent = []
        original = BoundCDP.call
        def observe(self, method, *args, **kwargs):
            sent.append(method)
            return original(self, method, *args, **kwargs)
        monkeypatch.setattr(BoundCDP, 'call', observe)
        try:
            with _profile_runtime_scope(selected_home, {}), pytest.raises(Exception):
                if adapter == 'code':
                    codes.discover('https://capture.test', 'Synthetic', nested.sup.task_id, parent=target)
                else:
                    pf.discover(nested.sup.task_id, target, 'https://capture.test')
            assert 'Target.attachToTarget' not in sent
            assert nested.sup._page_session_id == captured.previous
        finally:
            if unknown:
                unknown.close()
