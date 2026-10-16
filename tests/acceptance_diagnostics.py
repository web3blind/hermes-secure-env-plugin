"""Test-only, value-free wire-phase evidence. Never changes authority."""
from contextlib import contextmanager
from functools import wraps
import time

@contextmanager
def trace_fill(target, deadline, evidence, *, expire_phase=None):
    from secure_env_ingress import bound_cdp as b
    from hermes_constants import get_hermes_home
    from pathlib import Path
    raw=target.supervisor.raw
    cls=type(raw)
    original=cls.call
    started=time.monotonic()
    parent=target.lease.parent_session
    calls=[]
    evidence['wire']=dict(calls=0, refusals=[])
    wire=evidence['wire']
    def identity():
        return dict(captured_valid=raw.is_valid(), cancelled=bool(target.supervisor.cancelled and target.supervisor.cancelled.is_set()), lease_closed=target.lease.closed, parent_closed=parent.closed, profile_same=Path(get_hermes_home()).resolve()==parent.home, session_same=raw.page_session_id==parent.sid)
    @wraps(original)
    def call(self, method, params=None, *, session_id=None, timeout=None, before_send=None):
        if self is not raw:
            return original(self, method, params, session_id=session_id, timeout=timeout, before_send=before_send)
        wire['calls']+=1
        state=b._fill_diagnostic.get() or {}
        phase=state.get('stage','unknown')
        count=state.get('writes_confirmed',0)
        def checked():
            clock=b.time
            if expire_phase==phase and count>=2:
                from types import SimpleNamespace
                b.time=SimpleNamespace(monotonic=lambda: deadline+0.001)
            try:
                if before_send: before_send()
            except Exception as exc:
                wire['refusals'].append(dict(phase=phase, writes_confirmed=count, authorization_expired=str(exc)=='authorization expired', remaining=deadline-time.monotonic(), target_remaining=target.expires-time.monotonic(), elapsed=time.monotonic()-started, **identity()))
                raise
            finally:
                b.time=clock
        return original(self, method, params, session_id=session_id, timeout=timeout, before_send=checked)
    cls.call=call
    try:
        yield
    finally:
        cls.call=original
        wire['end']=dict(remaining=deadline-time.monotonic(),target_remaining=target.expires-time.monotonic(),elapsed=time.monotonic()-started,**identity())
