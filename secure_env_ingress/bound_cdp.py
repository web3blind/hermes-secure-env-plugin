"""Public captured-CDP transport with plugin-owned late cleanup workers.

The original handle is the only transport authority. Daemon workers retain
attachment and disposal responsibility after the caller's finite deadline.
"""
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import contextmanager
from copy import deepcopy
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
        # Abandoned reads retain their slot until the original raw call drains.
        # No executor queue, replacement pool, or unbounded shutdown wait.
        self._proof_slots = threading.BoundedSemaphore(4)

    def valid(self):
        try:
            return (self.raw.is_valid()
                    and not (self.cancelled is not None and self.cancelled.is_set()))
        except Exception:
            return False

    def check(self):
        if not self.valid():
            fill_diagnostic(reason='cancelled' if self.cancelled is not None and self.cancelled.is_set() else 'parent_changed')
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
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == 'function(i,v){return this.write(i,v)}':
                fill_diagnostic(attempted=True)
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

    def read_batch(self, requests):
        """Only retained, value-free nested proof reads; replies stay ordered.

        One finite barrier owns at most four daemon workers. Each raw call still
        uses _request's original wire-time identity/cancellation/TTL fences.
        Timed-out workers cannot dispatch more reads and retain their slots until
        drain; cleanup remains on the independent original-handle path.
        """
        requests = deepcopy(list(requests))
        # A guard verdict and its subsequent document census are dependent.
        # Keep batches homogeneous so callers cannot reorder those phases.
        if len({method for method, _, _ in requests}) > 1:
            raise ValueError('mixed proof phases')
        for method, params, sid in requests:
            allowed = (
                method == 'DOM.getFrameOwner' and set(params) == {'frameId'}
                and isinstance(params['frameId'], str)
                or method == 'DOM.describeNode' and set(params) == {'objectId', 'depth', 'pierce'}
                and isinstance(params['objectId'], str) and params['depth'] == 128
                and params['pierce'] is False
                or method == 'Runtime.callFunctionOn'
                and set(params) == {'objectId', 'functionDeclaration', 'arguments', 'returnByValue'}
                and isinstance(params['objectId'], str)
                and params['functionDeclaration'] == GUARD_VALIDATION
                and params['returnByValue'] is True and isinstance(params['arguments'], list)
                and all(isinstance(arg, dict) and set(arg) == {'objectId'}
                        and isinstance(arg['objectId'], str) for arg in params['arguments']))
            if not allowed or not isinstance(sid, str) or not sid:
                raise ValueError('inadmissible proof read')
        self.check()
        if not requests:
            return []
        count = min(4, len(requests))
        reserved = 0
        for _ in range(count):
            if not self._proof_slots.acquire(blocking=False):
                for _ in range(reserved):
                    self._proof_slots.release()
                raise ValueError('proof reads still draining')
            reserved += 1
        stopped, lock = threading.Event(), threading.Lock()
        deadline = time.monotonic() + CALL_TIMEOUT
        replies, cursor = [None] * len(requests), iter(enumerate(requests))
        def run():
            try:
                while True:
                    with lock:
                        if stopped.is_set():
                            return
                        item = next(cursor, None)
                    if item is None:
                        return
                    index, (method, params, sid) = item
                    replies[index] = self._request(method, params, sid,
                        stopped=stopped, deadline=deadline)
            except BaseException:
                stopped.set()
                raise
            finally:
                self._proof_slots.release()
        futures = []
        try:
            for _ in range(count):
                futures.append(self._worker(run))
                reserved -= 1
            for future in futures:
                future.result(max(0, deadline - time.monotonic()))
            self.check()
            if any(reply is None for reply in replies):
                raise ValueError('incomplete proof reads')
            return replies
        except FutureTimeout:
            raise TimeoutError('parent command timeout') from None
        finally:
            stopped.set()
            for _ in range(reserved):
                self._proof_slots.release()

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


GUARD_VALIDATION = 'function(...others){return this.valid()&&others.every(g=>g.document===this.document&&g.valid())}'
_fill_diagnostic = ContextVar('secure_env_fill_diagnostic', default=None)

@contextmanager
def fill_diagnostic_scope():
    # Private in-process metadata only. Never retain arguments or exceptions.
    state = dict(stage='acquire', reason='unconfirmed', writes_attempted=0, writes_confirmed=0)
    token = _fill_diagnostic.set(state)
    try:
        yield state
    finally:
        _fill_diagnostic.reset(token)


def fill_diagnostic(stage=None, reason=None, *, attempted=False, confirmed=False):
    import logging
    stages = ('acquire', 'revalidate', 'focus', 'write', 'readback', 'completion')
    reasons = ('unconfirmed', 'exception', 'expired', 'profile_refused', 'focus_refused',
               'write_unconfirmed', 'guard_refused', 'filled', 'cancelled',
               'parent_changed', 'loop_unavailable', 'socket_closed', 'cdp_timeout',
               'cdp_error', 'context_refused', 'attachment_abandoned', 'ownership_refused',
               'browser_unavailable', 'profile_changed', 'parent_session_changed')
    if stage is not None and stage not in stages or reason is not None and reason not in reasons:
        raise ValueError('invalid diagnostic')
    state = _fill_diagnostic.get()
    if state is None:
        if reason is not None:
            try:
                logging.getLogger(__name__).warning(
                    'secure_env_fill stage=%s reason=%s', stage or 'acquire', reason)
            except Exception:
                pass
        return
    if stage is not None:
        state['stage'] = stage
        state['reason'] = 'unconfirmed'
    if reason is not None:
        state['reason'] = reason
    state['writes_attempted'] += int(attempted)
    state['writes_confirmed'] += int(confirmed)


def log_fill_diagnostic(state):
    import logging
    try:
        logging.getLogger(__name__).warning(
            'secure_env_fill stage=%s reason=%s writes_attempted=%d writes_confirmed=%d',
            state['stage'], state['reason'], state['writes_attempted'], state['writes_confirmed'])
    except Exception:
        pass
