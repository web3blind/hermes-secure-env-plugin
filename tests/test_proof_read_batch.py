"""Bounded proof-only concurrency and original captured-wire fences."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
import json
from pathlib import Path
import threading
import time

import pytest
from test_parent_transport import transport as transport
from secure_env_ingress import bound_cdp as bc


def reads(count=8):
    return [('DOM.getFrameOwner', {'frameId': str(i)}, 'original-session') for i in range(count)]


class Raw:
    task_id = 'synthetic'
    page_session_id = 'original-session'
    cdp_url = 'ws://synthetic'
    def __init__(self):
        self.valid = True
        self.sent = []
        self.live = self.peak = 0
        self.lock = threading.Lock()
        self.entered = threading.Event()
        self.resume = None
        self.delay = 0
        self.context = None
    def is_valid(self):
        return self.valid
    def call(self, method, params, *, session_id=None, timeout=None, before_send=None):
        with self.lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
        try:
            self.entered.set()
            if self.resume is not None:
                assert self.resume.wait(2)
            if self.delay:
                time.sleep(self.delay)
            before_send()
            if self.context is not None:
                assert self.context.get() == 'original-profile'
            with self.lock:
                self.sent.append((method, params, session_id, timeout))
            return {'result': {'backendNodeId': params.get('frameId')}}
        finally:
            with self.lock:
                self.live -= 1


def drain(raw):
    end = time.monotonic() + 2
    while raw.live:
        assert time.monotonic() < end
        time.sleep(.005)


def test_order_metadata_context_and_bound():
    raw = Raw()
    raw.delay = .01
    raw.context = ContextVar('proof-test-profile')
    token = raw.context.set('original-profile')
    try:
        replies = bc.BoundCDP(raw).read_batch(reads(17))
    finally:
        raw.context.reset(token)
    assert [r['result']['backendNodeId'] for r in replies] == [str(i) for i in range(17)]
    assert raw.peak == 4 and raw.live == 0
    assert sorted(raw.sent, key=lambda r: int(r[1]['frameId'])) == [
        (m, p, sid, bc.REPLY_TIMEOUT) for m, p, sid in reads(17)]


@pytest.mark.parametrize('proof_request', [
    ('Runtime.evaluate', {'expression': '1'}, 's'),
    ('Runtime.callFunctionOn', {'objectId': 'g', 'functionDeclaration': 'function(){return this.focus(0)}', 'arguments': [], 'returnByValue': True}, 's'),
    ('Runtime.callFunctionOn', {'objectId': 'g', 'functionDeclaration': bc.GUARD_VALIDATION, 'arguments': [{'value': 'not-allowed'}], 'returnByValue': True}, 's'),
    ('DOM.resolveNode', {'backendNodeId': 1}, 's'),
    ('DOM.describeNode', {'objectId': 'd', 'depth': 128, 'pierce': True}, 's'),
    ('Target.attachToTarget', {'targetId': 'x'}, None),
    ('Runtime.releaseObject', {'objectId': 'g'}, 's'),
    ('Target.detachFromTarget', {'sessionId': 's'}, None),
])
def test_whitelist_validates_entire_batch_before_dispatch(proof_request):
    raw = Raw()
    with pytest.raises(ValueError):
        bc.BoundCDP(raw).read_batch(reads(1) + [proof_request])
    assert not raw.sent


def test_exact_guard_and_document_requests():
    raw = Raw()
    requests = [('Runtime.callFunctionOn', {'objectId': 'g', 'functionDeclaration': bc.GUARD_VALIDATION, 'arguments': [{'objectId': 'other'}], 'returnByValue': True}, 's'),
                ('DOM.describeNode', {'objectId': 'original-doc', 'depth': 128, 'pierce': False}, 's')]
    bound = bc.BoundCDP(raw)
    assert sum(len(bound.read_batch([request])) for request in requests) == 2
    assert sorted(raw.sent) == sorted((m, p, sid, bc.REPLY_TIMEOUT) for m, p, sid in requests)
    raw.sent.clear()
    with pytest.raises(ValueError, match='mixed proof phases'):
        bound.read_batch(requests)
    assert not raw.sent


@pytest.mark.parametrize('fence', ['expiry', 'cancel', 'identity'])
def test_original_wire_fences_after_queue(transport, fence):
    sup, wire, replacement, _ = transport
    entered, resume = threading.Event(), threading.Event()
    def stall():
        entered.set()
        resume.wait(2)
    sup._loop.call_soon_threadsafe(stall)
    assert entered.wait(1)
    cancelled = threading.Event()
    with bc.acquisition_scope(cancelled):
        bound = bc.BoundCDP(sup.handle)
    def batch():
        with bc.acquisition_scope(cancelled), bc.dispatch_scope(time.monotonic() + (.04 if fence == 'expiry' else 5)):
            return bound.read_batch(reads(8))
    try:
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(batch)
            time.sleep(.08)
            if fence == 'cancel':
                cancelled.set()
            elif fence == 'identity':
                sup.reconnect()
            resume.set()
            with pytest.raises(ValueError):
                future.result(2)
        assert not wire.commands and not replacement.commands
    finally:
        resume.set()


def test_timeout_abandonment_bounds_workers_late_sends_and_cleanup(monkeypatch):
    monkeypatch.setattr(bc, 'CALL_TIMEOUT', .04)
    raw = Raw()
    raw.resume = threading.Event()
    bound = bc.BoundCDP(raw)
    with pytest.raises(TimeoutError):
        bound.read_batch(reads(20))
    assert raw.live == 4
    with pytest.raises(ValueError, match='draining'):
        bound.read_batch(reads(20))
    assert raw.live == 4
    raw.resume.set()
    drain(raw)
    assert not raw.sent  # queued before_send rejects every abandoned read
    bound.dispose('original-session', wait=True)
    assert [r[0] for r in raw.sent] == ['Target.detachFromTarget']
    assert len(bound.read_batch(reads(1))) == 1


def test_failure_stops_queued_work_and_drains(monkeypatch):
    raw = Raw()
    original = raw.call
    def fail(method, params, **kwargs):
        if params.get('frameId') == '0':
            raise RuntimeError('lost read receipt')
        return original(method, params, **kwargs)
    monkeypatch.setattr(raw, 'call', fail)
    # Preserve the public signature required by capture admission.
    import functools
    raw.call = functools.wraps(original)(fail)
    bound = bc.BoundCDP(raw)
    with pytest.raises(ValueError):
        bound.read_batch(reads(20))
    drain(raw)
    assert not raw.sent
    assert bound.read_batch(reads(0)) == []


def test_deterministic_injected_read_delay():
    receipt = {}
    requests = reads(16)
    for mode in ('unchanged_sequential', 'bounded_batch'):
        raw = Raw()
        raw.delay = .02
        bound = bc.BoundCDP(raw)
        start = time.monotonic()
        replies = ([bound.call(m, p, sid) for m, p, sid in requests]
                   if mode == 'unchanged_sequential' else bound.read_batch(requests))
        receipt[mode] = {'seconds': time.monotonic()-start, 'peak': raw.peak, 'calls': len(raw.sent)}
        assert len(replies) == 16
    assert receipt['bounded_batch']['seconds'] < receipt['unchanged_sequential']['seconds'] * .65
    (Path.home()/'proof-delay.json').write_text(json.dumps(receipt, indent=2))
    print('PROOF_DELAY ' + json.dumps(receipt), flush=True)


def test_request_snapshot_cannot_be_changed_while_queued():
    raw = Raw()
    raw.resume = threading.Event()
    bound = bc.BoundCDP(raw)
    requests = [('Runtime.callFunctionOn', {'objectId': 'g', 'functionDeclaration': bc.GUARD_VALIDATION, 'arguments': [{'objectId': 'other'}], 'returnByValue': True}, 'original-session')]
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(bound.read_batch, requests)
        assert raw.entered.wait(1)
        requests[0][1]['functionDeclaration'] = 'function(){this.write(0,"x")}'
        requests[0][1]['arguments'][0]['objectId'] = 'different'
        raw.resume.set()
        future.result(1)
    assert raw.sent[0][1]['functionDeclaration'] == bc.GUARD_VALIDATION
    assert raw.sent[0][1]['arguments'] == [{'objectId': 'other'}]
