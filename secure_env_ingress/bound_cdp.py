"""Plugin-local CDP transport pinned to one supervisor connection.

The host reader owns response demultiplexing; commands never use host _cdp's
mutable websocket. An attachment owns its late reply before it is sent. Timeouts
abandon acquisition, not responsibility for disposing that exact session.
"""
import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import json
import threading

CALL_TIMEOUT = 6
REPLY_TIMEOUT = 5
_cancelled = ContextVar('secure_env_acquisition_cancelled', default=None)


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


class BoundCDP:
    def __init__(self, sup):
        self.raw = sup
        self.ws, self._loop, self.browser = sup._ws, sup._loop, sup.cdp_url
        self.cancelled = _cancelled.get()

    def valid(self):
        return (self.raw._active and self.raw._ws is self.ws and self.raw._loop is self._loop
                and self.raw.cdp_url == self.browser and self.ws is not None
                and not (self.cancelled is not None and self.cancelled.is_set()))

    def check(self):
        if not self.valid():
            raise ValueError('parent connection changed or discovery cancelled')

    def socket_closed(self):
        return (getattr(self.ws, 'closed', False) is True
                or getattr(getattr(self.ws, 'state', None), 'name', None) == 'CLOSED')

    async def _request(self, method, params, sid, *, cleanup=False, acquisition=None):
        sup = self.raw
        # This executes on the captured loop. No await intervenes between this
        # fence and dispatch. Even if send suspends, it uses the captured wire.
        if cleanup:
            if self.socket_closed():
                raise ValueError('parent connection closed')
        else:
            self.check()
            if acquisition is not None and acquisition.abandoned:
                raise ValueError('attachment cancelled')
        call_id, sup._next_call_id = sup._next_call_id, sup._next_call_id + 1
        payload = {'id': call_id, 'method': method}
        payload.update({k: v for k, v in (('params', params), ('sessionId', sid)) if v})
        fut = asyncio.get_running_loop().create_future()
        sup._pending_calls[call_id] = fut
        try:
            await self.ws.send(json.dumps(payload))
            if acquisition is None:
                result = await asyncio.wait_for(fut, REPLY_TIMEOUT)
            else:
                # Do not cancel/drop an attach response at the inner CDP deadline.
                # It may be the only way to identify the exact acquired session.
                while not fut.done():
                    if self.socket_closed():
                        raise ValueError('parent connection closed')
                    await asyncio.wait({fut}, timeout=.1)
                result = fut.result()
                attached = result.get('result', {}).get('sessionId')
                if attached:
                    if not acquisition.finish(attached):
                        await self._request('Target.detachFromTarget', {'sessionId': attached}, None, cleanup=True)
                        raise ValueError('attachment cancelled')
            if not cleanup:
                self.check()  # Never accept a result from a changed generation.
            return result
        except BaseException:
            if acquisition is not None:
                acquisition.abandon()
            raise
        finally:
            sup._pending_calls.pop(call_id, None)

    def dispose(self, sid, *, wait=False):
        # Cleanup is exact and can use only the captured socket, even after the
        # supervisor moved on. It never touches the replacement/default/sibling.
        if self._loop is None or self._loop.is_closed() or self.socket_closed():
            return
        async def cleanup():
            try:
                await self._request('Target.detachFromTarget', {'sessionId': sid}, None, cleanup=True)
            except Exception:
                pass
        future = asyncio.run_coroutine_threadsafe(cleanup(), self._loop)
        if wait:
            try:
                future.result(CALL_TIMEOUT)
            except Exception:
                pass  # The queued cleanup retains responsibility after timeout.

    def close_object(self, sid, obj, *, inspection=False):
        """Internal disposal only: fixed guard close, then independent release.

        No caller-supplied JS can cross this cancellation fence. The queued
        disposal owns both attempts even after its synchronous caller times out.
        """
        if self._loop is None or self._loop.is_closed() or self.socket_closed():
            return
        function = ('function(){this.guard.close();return true;}' if inspection else
                    'function(){if(this.close)this.close();return true;}')
        async def cleanup():
            try:
                await self._request('Runtime.callFunctionOn', {'objectId': obj,
                    'functionDeclaration': function, 'returnByValue': True}, sid, cleanup=True)
            except Exception:
                pass
            try:
                await self._request('Runtime.releaseObject', {'objectId': obj}, sid, cleanup=True)
            except Exception:
                pass
        future = asyncio.run_coroutine_threadsafe(cleanup(), self._loop)
        try:
            future.result(CALL_TIMEOUT)
        except Exception:
            pass  # Retain exact captured-wire cleanup, never cancel it.

    def call(self, method, params=None, sid=None):
        if self._loop is None or self._loop.is_closed():
            raise ValueError('parent connection unavailable')
        acquisition = _Acquisition(self) if method == 'Target.attachToTarget' else None
        cleanup = method in ('Target.detachFromTarget', 'Runtime.releaseObject')
        future = asyncio.run_coroutine_threadsafe(
            self._request(method, params or {}, sid, acquisition=acquisition, cleanup=cleanup), self._loop)
        try:
            result = future.result(CALL_TIMEOUT)
            if not cleanup:
                self.check()
            if acquisition is not None:
                acquisition.claim()
            return result
        except BaseException:
            if acquisition is not None:
                acquisition.abandon()
            else:
                if not cleanup:
                    future.cancel()
            raise
