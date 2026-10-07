"""Public captured-CDP transport with plugin-owned late cleanup workers.

The original handle is the only transport authority. Daemon workers retain
attachment and disposal responsibility after the caller's finite deadline.
"""
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
import inspect
import threading
import time

CALL_TIMEOUT = 6
REPLY_TIMEOUT = 5
_cancelled = ContextVar('secure_env_acquisition_cancelled', default=None)
_deadline = ContextVar('secure_env_dispatch_deadline', default=None)


class FrameUnavailable(ValueError):
    """Fixed signal for exact OOPIF attachment, without raw CDP error text."""


@contextmanager
def dispatch_scope(deadline):
    old = _deadline.get()
    token = _deadline.set(deadline if old is None else min(old, deadline))
    try:
        yield
    finally:
        _deadline.reset(token)


@contextmanager
def acquisition_scope(cancelled):
    token = _cancelled.set(cancelled)
    try:
        yield
    finally:
        _cancelled.reset(token)


class _Acquisition:
    def __init__(self, transport):
        self.transport = transport
        self.lock = threading.Lock()
        self.abandoned, self.sid = False, None

    def finish(self, sid):
        with self.lock:
            if self.abandoned:
                return False
            self.sid = sid
            return True

    def claim(self):
        with self.lock:
            if self.abandoned:
                raise ValueError('attachment cancelled')
            self.sid = None

    def abandon(self):
        with self.lock:
            self.abandoned = True
            sid, self.sid = self.sid, None
        if sid:
            self.transport.dispose(sid)


def require_capture(handle):
    """Refuse old hosts before any command, without private compatibility paths."""
    try:
        if not callable(handle.is_valid) or not callable(handle.call):
            raise ValueError
        parameters = inspect.signature(handle.call).parameters
        if not {'session_id', 'timeout', 'before_send'} <= parameters.keys():
            raise ValueError
        if not handle.task_id or not handle.page_session_id or not handle.cdp_url or not handle.is_valid():
            raise ValueError
    except Exception:
        raise ValueError('public browser capture unavailable') from None


class BoundCDP:
    def __init__(self, handle):
        require_capture(handle)
        self.raw = handle
        self.browser = handle.cdp_url
        self.task_id, self.page_session_id = handle.task_id, handle.page_session_id
        self.cancelled = _cancelled.get()

    def valid(self):
        try:
            return (self.raw.is_valid()
                    and not (self.cancelled is not None and self.cancelled.is_set()))
        except Exception:
            return False

    def check(self):
        if not self.valid():
            raise ValueError('parent connection changed or discovery cancelled')

    def _request(self, method, params, sid, *, cleanup=False, acquisition=None,
                 stopped=None, deadline=None):
        operation_cancelled, authorization_deadline = _cancelled.get(), _deadline.get()
        def before_send():
            # Pure/nonblocking trusted dispatch hook; never capture or call CDP.
            if not cleanup:
                self.check()
                if operation_cancelled is not None and operation_cancelled.is_set():
                    raise ValueError('operation cancelled')
                if authorization_deadline is not None and time.monotonic() >= authorization_deadline:
                    raise ValueError('authorization expired')
                if (stopped is not None and stopped.is_set()
                        or acquisition is not None and acquisition.abandoned):
                    raise ValueError('attachment cancelled')
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('parent dispatch timeout')
        try:
            result = self.raw.call(method, params, session_id=sid,
                timeout=None if acquisition is not None or cleanup else REPLY_TIMEOUT,
                before_send=before_send)
            if acquisition is not None:
                attached = result.get('result', {}).get('sessionId')
                if attached and not acquisition.finish(attached):
                    self.dispose(attached)
                    raise ValueError('attachment cancelled')
            if not cleanup:
                self.check()
            return result
        except TimeoutError:
            if acquisition is not None:
                acquisition.abandon()
            raise TimeoutError('parent command timeout') from None
        except RuntimeError as error:
            if acquisition is not None:
                acquisition.abandon()
            message = error.args[0] if error.args else None
            if method == 'Page.createIsolatedWorld' and isinstance(message, str) and 'No frame for given id found' in message:
                raise FrameUnavailable('frame unavailable') from None
            raise ValueError('parent connection changed or command refused') from None
        except Exception:
            if acquisition is not None:
                acquisition.abandon()
            raise ValueError('parent connection changed or discovery cancelled') from None

    @staticmethod
    def _worker(function):
        future, context = Future(), copy_context()
        def run():
            try:
                future.set_result(context.run(function))
            except BaseException as error:
                future.set_exception(error)
        threading.Thread(target=run, name='secure-env-cdp', daemon=True).start()
        return future

    def dispose(self, sid, *, wait=False):
        # Invalidation never permits cleanup on a replacement connection.
        def cleanup():
            try:
                self._request('Target.detachFromTarget', {'sessionId': sid}, None, cleanup=True)
            except Exception:
                pass
        future = self._worker(cleanup)
        if wait:
            try:
                future.result(CALL_TIMEOUT)
            except Exception:
                pass  # The worker retains responsibility after caller timeout.

    def close_object(self, sid, obj, *, inspection=False):
        """Fixed guard close and independent release, retained after timeout."""
        function = ('function(){this.guard.close();return true;}' if inspection else
                    'function(){if(this.close)this.close();return true;}')
        def cleanup():
            try:
                closing = self._worker(lambda: self._request('Runtime.callFunctionOn', {'objectId': obj,
                    'functionDeclaration': function, 'returnByValue': True}, sid, cleanup=True))
                closing.result(REPLY_TIMEOUT)
            except Exception:
                pass
            try:
                self._request('Runtime.releaseObject', {'objectId': obj}, sid, cleanup=True)
            except Exception:
                pass
        future = self._worker(cleanup)
        try:
            future.result(CALL_TIMEOUT)
        except Exception:
            pass  # Never cancel the exact original-handle cleanup.

    def call(self, method, params=None, sid=None):
        acquisition = _Acquisition(self) if method == 'Target.attachToTarget' else None
        cleanup = method in ('Target.detachFromTarget', 'Runtime.releaseObject')
        stopped = threading.Event()
        deadline = time.monotonic() + CALL_TIMEOUT
        future = self._worker(lambda: self._request(method, params or {}, sid,
            acquisition=acquisition, cleanup=cleanup, stopped=stopped, deadline=deadline))
        try:
            result = future.result(CALL_TIMEOUT)
            if not cleanup:
                self.check()
            if acquisition is not None:
                acquisition.claim()
            return result
        except FutureTimeout:
            if not cleanup:
                stopped.set()
            if acquisition is not None:
                acquisition.abandon()
            raise TimeoutError('parent command timeout') from None
        except BaseException:
            if not cleanup:
                stopped.set()
            if acquisition is not None:
                acquisition.abandon()
            raise
