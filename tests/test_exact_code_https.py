"""Real registered tool, authorized delivery, HTTPS UI and isolated Chromium."""
import asyncio
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from generic_helpers import registered
from test_runtime_e2e import make_runtime, post
from test_tool_https_e2e import running_gateway_loop


@pytest.mark.parametrize('case', ['input', 'textarea', 'plaintext', 'editable', 'editable100multiline', 'textarea100multiline', 'ordered100', 'indexed100', 'ordered6nomax', 'indexed6nomax', 'ordered100nomax', 'indexed100nomax', 'unconfirmed', 'length_mismatch', 'mutation', 'cancel'])
def test_registered_exact_https(nested, tmp_path, monkeypatch, caplog, pytestconfig, case):
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry
    from secure_env_ingress import runtime as runtime_module

    origin, leaf = setup_chain(nested)
    cells = case in ('ordered100', 'indexed100', 'ordered6nomax', 'indexed6nomax', 'ordered100nomax', 'indexed100nomax')
    count = 6 if case.endswith('6nomax') else 100
    multiline = case.startswith(('textarea', 'plaintext', 'editable'))
    value = ''.join(chr(33+i%90) for i in range(count)) if cells else 'A\nБ🙂'*25 if case.endswith('100multiline') else 'A\nБ🙂' if multiline else '!'
    target = spec(len(value), 'ordered_cells' if case.startswith('ordered') else 'indexed_cells' if cells else 'single', multiline)
    if cells:
        capacity = '' if case.endswith('nomax') else ' maxlength="1"'
        markup = '<div id="group">'+''.join(f'<div><input id="c{i}"{capacity}></div><span>decoration</span>' for i in range(count))+'</div>'
    elif case.startswith('textarea'):
        markup = '<textarea id="challenge"></textarea>'
    elif case == 'plaintext':
        markup = '<div id="challenge" contenteditable="plaintext-only"></div>'
    elif case.startswith('editable'):
        markup = '<div id="challenge" contenteditable="true"></div>'
    else:
        markup = '<input id="challenge">'
    leaf.evaluate('(s)=>document.body.innerHTML=s', markup)
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    monkeypatch.setenv('HERMES_HOME', str(home))
    factory = runtime_module.IngressRuntime
    runtimes = []
    import time
    from secure_env_ingress import vault_ingress
    original_fill = vault_ingress.fill_verification_code
    fill_evidence = {}
    def measured_fill(target, value, *, expires_at):
        deadline = expires_at
        started = time.monotonic()
        fill_evidence['remaining_at_start'] = deadline-started
        try:
            from acceptance_diagnostics import trace_fill
            with trace_fill(target, deadline, fill_evidence):
                answer = original_fill(target, value, expires_at=deadline)
            fill_evidence['returned'] = answer
            return answer
        except Exception as exc:
            fill_evidence['error_type'] = type(exc).__name__
            raise
        finally:
            fill_evidence['seconds'] = time.monotonic()-started
            # Safe timing receipt survives a failing HTTP assertion. Never cache
            # the supplied value, bearer token, selectors or control contents.
            pytestconfig.cache.set('senv_exact_fill_attempt/'+case, dict(fill_evidence))
    monkeypatch.setattr(vault_ingress, 'fill_verification_code', measured_fill)
    def make(cfg, h, token):
        runtime = factory(cfg, h, token, trust_roots=root)
        runtimes.append(runtime)
        return runtime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', make)
    sent = []
    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            sent.append(True)
            assert chat_id == '-600'
            url = content.split('form: ', 1)[1].split(' for ', 1)[0]
            token = urlsplit(url).fragment
            status, descriptor = await asyncio.to_thread(post, settings, root, '/session', {'token': token, 'initData': ''})
            assert status == 200 and descriptor['target']['confirmation_required'] is True
            assert descriptor['target']['validation'] == target['validation']
            if case == 'mutation':
                from secure_env_ingress.nested_code import _invoke
                retained = next(iter(runtimes[-1]._targets.values()))
                _invoke(retained.supervisor, retained.leaf_sid, retained.leaf_guard,
                    'function(){const e=this.document.querySelector("input");e.id="other";e.id="challenge"}')
            if case == 'cancel':
                await asyncio.to_thread(runtimes[-1].cancel, ('telegram', '7'))
                from secure_env_ingress.server import HTTPError
                with pytest.raises(HTTPError) as rejection:
                    runtimes[-1].session(token, '')
                assert rejection.value.status == 410
            elif case in ('unconfirmed', 'length_mismatch', 'mutation'):
                status, body = await asyncio.to_thread(post, settings, root, '/submit', {'token': token, 'initData': '', 'values': [value+'!' if case == 'length_mismatch' else value], 'confirmed': case != 'unconfirmed'}, timeout=120)
                assert status == (409 if case == 'mutation' else 400), body
            return SimpleNamespace(success=True)

    # HTTPS submission is performed in the authorized adapter, not model args.
    # Playwright cannot be invoked from the gateway's thread. Use HTTP for registry
    # acceptance; exercise the exact shipped client separately below.
    async def submit_after_delivery(chat_id, content, metadata=None):
        if case in ('unconfirmed', 'length_mismatch', 'mutation', 'cancel'):
            return await Adapter().send(chat_id, content, metadata)
        sent.append(True)
        assert chat_id == '-600'
        token = urlsplit(content.split('form: ', 1)[1].split(' for ', 1)[0]).fragment
        status, descriptor = await asyncio.to_thread(post, settings, root, '/session', {'token': token, 'initData': ''})
        assert status == 200 and descriptor['target']['validation'] == target['validation']
        status, body = await asyncio.to_thread(post, settings, root, '/submit', {'token': token, 'initData': '', 'values': [value], 'confirmed': True}, timeout=180)
        assert (status, body) == (200, {'filled': True})
        return SimpleNamespace(success=True)

    pending_submissions = []
    async def send(chat_id, content, metadata=None):
        # Delivery receipt is not secret submission completion. The real user
        # submits later; never hold the gateway's bounded send acknowledgement
        # open for the entire 100-cell fill.
        pending_submissions.append(asyncio.create_task(submit_after_delivery(chat_id, content, metadata)))
        return SimpleNamespace(success=True)
    async def drained_submissions():
        await asyncio.gather(*pending_submissions)

    with running_gateway_loop() as loop, registered(monkeypatch, home, settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM: SimpleNamespace(send=send)}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM, user_id='7', chat_id='-600', chat_type='group'), text='synthetic')
        invoke_hook('pre_gateway_dispatch', event=event, gateway=gateway)
        tokens = sc.set_session_vars(platform='telegram', user_id='7', chat_id='-600', chat_type='group', session_id=nested.sup.task_id, session_key='key', cron_session='')
        try:
            raw = registry.dispatch('secure_env_vault', {'origin': origin, 'label': 'Synthetic', 'mode': 'code', 'parent': nested.parent, 'target_spec': target}, task_id=nested.sup.task_id, session_id=nested.sup.task_id)
        finally:
            sc.clear_session_vars(tokens)
        asyncio.run_coroutine_threadsafe(drained_submissions(), loop).result(timeout=180)
    result = json.loads(raw)
    pytestconfig.cache.set('senv_exact_diagnostic/'+case, {'result': result, 'fill': fill_evidence, 'write_count': leaf.evaluate('Array.from(document.querySelectorAll("input,textarea,[contenteditable]")).filter(e=>(e.value??e.textContent).length>0).length')})
    assert len(sent) == 1, result
    assert result['status'] == ('cancelled' if case == 'cancel' else 'unknown' if case == 'mutation' else 'rejected' if case in ('unconfirmed', 'length_mismatch') else 'filled'), result
    actual = leaf.evaluate('Array.from(document.querySelectorAll("input,textarea,[contenteditable]"),e=>e.value??e.textContent).join("")')
    assert actual == ('' if case in ('cancel', 'mutation', 'unconfirmed', 'length_mismatch') else value[::-1] if case.startswith('ordered') else value)
    assert value not in raw and '#challenge' not in raw
    assert not (home / 'vault').exists() and not (home / '.env').exists()
    if len(value) > 1:
        assert value not in caplog.text
    pytestconfig.cache.set('secure_env_exact/registered/'+case, result)
