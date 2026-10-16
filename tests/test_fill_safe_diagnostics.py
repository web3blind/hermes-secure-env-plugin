"""No accounts: registered HTTPS, real Chromium, bounded private fill receipts."""
import asyncio
import json
import logging
import re
import threading
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from test_nested_code import nested as nested, setup_chain
from test_indexed_react_browser import prepare, complete
from secure_env_ingress import bound_cdp, nested_code


@contextmanager
def faulting_diagnostic_logger():
    """Retain only safe records; fail emission without rendering the exception."""
    class UnrenderableError(OSError):
        def __str__(self):
            raise AssertionError('logging exception must never be rendered')

    records = []
    class FaultingHandler(logging.Handler):
        def emit(self, record):
            assert not record.exc_info and not record.stack_info
            records.append(record.getMessage())
            raise UnrenderableError('synthetic-private-logger-marker')

    logger = logging.getLogger('secure_env_ingress.bound_cdp')
    handler = FaultingHandler()
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        handler.close()


@pytest.mark.parametrize('case,attempted,confirmed,stage,reason', [
    ('success', 6, 6, 'completion', 'filled'),
    ('fault_success', 6, 6, 'completion', 'filled'),
    ('fault_false', 0, 0, 'focus', 'focus_refused'),
    ('fault_timeout', 1, 0, 'write', 'write_unconfirmed'),
    ('delayed', 6, 6, 'completion', 'filled'),
    ('focus_zero', 0, 0, 'focus', 'focus_refused'),
    ('focus_one', 1, 1, 'readback', 'write_unconfirmed'),
    ('focus_three', 3, 3, 'readback', 'write_unconfirmed'),
    ('lost_receipt', 1, 0, 'write', 'write_unconfirmed'),
    ('cancelled', 0, 0, 'revalidate', 'cancelled'),
    ('profile', 0, 0, 'acquire', 'profile_refused'),
    ('invalid_ui', 6, 6, 'completion', 'filled'),
    ('navigation', 6, 6, 'readback', 'write_unconfirmed'),
])
def test_registered_diagnostic(nested, tmp_path, monkeypatch, caplog,
                               case, attempted, confirmed, stage, reason):
    from generic_helpers import registered
    from test_runtime_e2e import make_runtime, post
    from test_tool_https_e2e import running_gateway_loop
    from secure_env_ingress import runtime as runtime_module, vault_ingress
    from gateway import session_context as sc
    from gateway.run import _profile_runtime_scope
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from gateway.session import SessionSource
    from hermes_cli.lifecycle import invoke_hook
    from tools.registry import registry

    fault = case.startswith('fault_')
    case = {'fault_success': 'success', 'fault_false': 'focus_zero',
            'fault_timeout': 'timeout'}.get(case, case)
    origin, leaf = setup_chain(nested, split=True)
    prepare(leaf)
    if case.startswith('focus_'):
        nested.page.evaluate('document.body.insertAdjacentHTML("beforeend", "<button id=exit>Elsewhere</button>")')
        index, event = {'focus_zero': (0, 'focus'), 'focus_one': (0, 'input'), 'focus_three': (2, 'input')}[case]
        leaf.evaluate('([i,event])=>{for(const name of event==="input"?["input","change"]:[event])document.querySelectorAll("input")[i].addEventListener(name,e=>{e.stopImmediatePropagation();top.document.querySelector("#exit").focus()},{once:true})}', [index, event])
    elif case == 'invalid_ui':
        leaf.evaluate('document.querySelectorAll("input")[5].addEventListener("input",()=>{document.body.appendChild(document.createElement("p")).textContent="Invalid code"})')
    elif case == 'navigation':
        # Synchronous post-input navigation invalidates the retained final proof.
        leaf.evaluate('document.querySelectorAll("input")[5].addEventListener("input",()=>{history.replaceState({},"","/done")})')
    original_invoke = nested_code._invoke
    if case in ('lost_receipt', 'timeout'):
        class SecretError(Exception):
            def __str__(self):
                raise AssertionError('exception must never be rendered')
        def lost(*args, **kwargs):
            result = original_invoke(*args, **kwargs)
            if args[3] == 'function(i,v){return this.write(i,v)}':
                if case == 'timeout':
                    raise TimeoutError('synthetic-private-timeout-marker')
                raise SecretError('synthetic-private-exception-marker')
            return result
        monkeypatch.setattr(nested_code, '_invoke', lost)
    sample, settings, home, root = make_runtime(tmp_path, mini=False)
    sample.close()
    if case == 'delayed':
        settings['ttl_seconds'] = 240  # Supported code cap; production unchanged.
    monkeypatch.setenv('HERMES_HOME', str(home))
    factory = runtime_module.IngressRuntime
    monkeypatch.setattr(runtime_module, 'IngressRuntime', lambda cfg,h,token: factory(cfg,h,token,trust_roots=root))
    if case in ('cancelled', 'profile'):
        original_fill = vault_ingress.fill_verification_code
        def changed(target, code, _fill=original_fill, **kwargs):
            target.supervisor.cancelled.set()
            return _fill(target, code, **kwargs)
        if case == 'cancelled':
            monkeypatch.setattr(vault_ingress, 'fill_verification_code', changed)
        else:
            import hermes_constants
            original_home = hermes_constants.get_hermes_home
            def profile_home():
                return home / 'other-profile' if bound_cdp._fill_diagnostic.get() is not None else original_home()
            monkeypatch.setattr(hermes_constants, 'get_hermes_home', profile_home)
    original_fill = vault_ingress.fill_verification_code
    callback_proofs = []
    def callback_context(target, code, **kwargs):
        from hermes_constants import get_hermes_home
        callback_proofs.append((get_hermes_home() == home,
            sc._SESSION_USER_ID.get() == '7', target.supervisor.cancelled is not None))
        return original_fill(target, code, **kwargs)
    if case != 'profile':
        monkeypatch.setattr(vault_ingress, 'fill_verification_code', callback_context)
    context_resets = []
    submit_code = factory._submit_code
    def checked_submit(runtime, *args, **kwargs):
        before = (bound_cdp._fill_diagnostic.get(), bound_cdp._cancelled.get(),
                  sc._SESSION_USER_ID.get())
        assert before[0] is None
        try:
            return submit_code(runtime, *args, **kwargs)
        finally:
            assert bound_cdp._fill_diagnostic.get() is before[0]
            assert bound_cdp._cancelled.get() is before[1]
            assert sc._SESSION_USER_ID.get() == before[2]
            context_resets.append(True)
    monkeypatch.setattr(factory, '_submit_code', checked_submit)
    pending = []
    sent = []
    succeeds = case in ('success', 'delayed', 'invalid_ui')
    class Adapter:
        async def send(self, chat_id, content, metadata=None):
            token = urlsplit(content.split('form: ',1)[1].split(' for ',1)[0]).fragment
            async def submit_later():
                # Real callback-thread HTTP after send acknowledgement, not inside send.
                await asyncio.sleep(172 if case == 'delayed' else .15)
                return await asyncio.to_thread(post, settings, root, '/submit',
                    {'token': token, 'initData': '', 'values': ['123456']}, timeout=60)
            pending.append(asyncio.create_task(submit_later()))
            sent.append(True)
            return SimpleNamespace(success=True)
    caplog.set_level('WARNING', logger='secure_env_ingress.bound_cdp')
    logging_scope = faulting_diagnostic_logger() if fault else nullcontext([])
    with logging_scope as fault_records, running_gateway_loop() as loop, registered(monkeypatch,home,settings=settings) as (_, gateway), _profile_runtime_scope(home, {}):
        gateway._gateway_loop = loop
        gateway.adapters = {Platform.TELEGRAM: Adapter()}
        event = MessageEvent(source=SessionSource(platform=Platform.TELEGRAM,user_id='7',chat_id='-600',chat_type='group'),text='synthetic')
        invoke_hook('pre_gateway_dispatch',event=event,gateway=gateway)
        tokens=sc.set_session_vars(platform='telegram',user_id='7',chat_id='-600',chat_type='group',session_id=nested.sup.task_id,session_key='key',cron_session='')
        try:
            raw=registry.dispatch('secure_env_vault', {'origin':origin,'label':'Synthetic','mode':'code','parent':nested.parent}, task_id=nested.sup.task_id,session_id=nested.sup.task_id)
            result=json.loads(raw)
            assert result['status']==('filled' if succeeds else 'unknown') and len(sent)==1, result
            async def drain():
                return await asyncio.gather(*pending)
            replies=asyncio.run_coroutine_threadsafe(drain(),loop).result(65)
            assert replies==[(200,{'filled':True})] if succeeds else replies==[(409,{'error':'fill_unconfirmed'})]
        finally:
            sc.clear_session_vars(tokens)
    assert context_resets == [True]
    assert bound_cdp._fill_diagnostic.get() is None
    assert bound_cdp._cancelled.get() is None
    if case != 'profile':
        assert callback_proofs == [(True, True, True)]
    records=[r.getMessage() for r in caplog.records if r.name=='secure_env_ingress.bound_cdp' and 'writes_attempted=' in r.getMessage()]
    if fault:
        records = fault_records
    assert records==[f'secure_env_fill stage={stage} reason={reason} writes_attempted={attempted} writes_confirmed={confirmed}']
    assert all(re.fullmatch(r'secure_env_fill stage=[a-z]+ reason=[a-z_]+ writes_attempted=\d+ writes_confirmed=\d+', s) for s in records)
    assert '123456' not in '\n'.join(records) and 'synthetic-private' not in '\n'.join(records)
    assert all(marker not in caplog.text for marker in
        ('123456', 'synthetic-private', origin))
    assert not (home/'vault').exists()
    if succeeds:
        complete(leaf)
    elif case != 'navigation':
        expected={'focus_zero':0,'focus_one':1,'focus_three':3,'lost_receipt':1,'timeout':1,'cancelled':0,'profile':0}[case]
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).filter(e=>e.value!=="").length')==expected


def test_faulting_logger_preserves_outside_scope_refusal(caplog):
    from public_capture_helpers import PublicRegistry
    sup = PublicRegistry().capture('task')
    cancelled = threading.Event()
    assert bound_cdp._fill_diagnostic.get() is None
    assert bound_cdp._cancelled.get() is None
    with faulting_diagnostic_logger() as records:
        with bound_cdp.acquisition_scope(cancelled):
            bound = bound_cdp.BoundCDP(sup)
            cancelled.set()
            with pytest.raises(ValueError, match='^parent connection changed or discovery cancelled$'):
                bound.check()
            assert bound_cdp._cancelled.get() is cancelled
            assert bound_cdp._fill_diagnostic.get() is None
    assert bound_cdp._cancelled.get() is None
    assert bound_cdp._fill_diagnostic.get() is None
    assert records == ['secure_env_fill stage=acquire reason=cancelled']
    assert 'synthetic-private' not in caplog.text


def test_diagnostic_allowlist_and_context_isolation():
    with bound_cdp.fill_diagnostic_scope() as first:
        with pytest.raises(ValueError):
            bound_cdp.fill_diagnostic(reason='non-allowlisted-private-value')
        bound_cdp.fill_diagnostic('write',attempted=True)
        with bound_cdp.fill_diagnostic_scope() as second:
            assert second['writes_attempted']==0
        assert first['writes_attempted']==1
    assert bound_cdp._fill_diagnostic.get() is None


def test_swallowed_top_level_valueerror_retains_diagnostic(nested, monkeypatch, tmp_path):
    import threading
    from secure_env_ingress import code_targets as codes
    setup_chain(nested)
    prepare(nested.page)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    batch = threading.Event()
    selection = codes.CodeSelection()
    target, response = selection.choose(('synthetic',), 'https://parent.test',
        'Synthetic', nested.sup.task_id, batch=batch)
    assert response is None and not target.explicit_parent
    try:
        batch.set()
        with bound_cdp.fill_diagnostic_scope() as state:
            # Real no-parent ValueError is swallowed by code_targets.fill.
            assert not codes.fill(target, '123456', __import__('time').monotonic()+20)
            assert state['reason'] == 'cancelled'
            assert state['writes_attempted'] == state['writes_confirmed'] == 0
        assert nested.page.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="")')
    finally:
        codes.release(target)
        selection.close()
