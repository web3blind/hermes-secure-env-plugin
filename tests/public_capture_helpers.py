"""Synchronous synthetic implementation of the host's public captured-CDP seam.

Every capture returns a fresh handle, even when the connection/page is unchanged.
No supervisor internals, event loop, socket, or call table are exposed.
"""
from dataclasses import dataclass, field


@dataclass
class PublicConnection:
    task_id: str = 'task'
    cdp_url: str = 'ws://synthetic-browser'
    page_session_id: str = 'page'
    evaluate: object = field(default=lambda expression: 'https://site.test/login')
    valid: bool = True
    calls: list = field(default_factory=list)


class PublicCapture:
    def __init__(self, registry, connection):
        self.task_id = connection.task_id
        self.cdp_url = connection.cdp_url
        self.page_session_id = connection.page_session_id
        self._registry = registry
        self._connection = connection
        self.valid = registry.capture_valid
        self.calls = []

    def is_valid(self):
        return (self.valid and self._connection.valid
                and self._registry.connection is self._connection)

    def call(self, method, params=None, *, session_id=None, timeout=10.0,
             before_send=None):
        if not self.is_valid():
            raise RuntimeError('synthetic captured connection invalid')
        if before_send is not None:
            before_send()
        if not self.is_valid():
            raise RuntimeError('synthetic captured connection invalid')
        assert method == 'Runtime.evaluate', method
        assert session_id == self.page_session_id
        assert isinstance(params, dict)
        assert params['returnByValue'] is True
        call = (method, params, session_id, timeout)
        self.calls.append(call)
        self._connection.calls.append(call)
        value = self._connection.evaluate(params['expression'])
        return {'id': len(self._connection.calls),
                'result': {'result': {'value': value}}}


class PublicRegistry:
    def __init__(self, connection=None):
        self.connection = connection or PublicConnection()
        self.capture_valid = True
        self.handles = []

    def capture(self, task_id, *, timeout=10.0):
        if self.connection is None or self.connection.task_id != task_id:
            raise RuntimeError('synthetic browser unavailable')
        handle = PublicCapture(self, self.connection)
        self.handles.append(handle)
        return handle


def install_public_registry(monkeypatch, connection=None):
    from tools import browser_supervisor
    registry = PublicRegistry(connection)
    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'capture',
                        registry.capture)

    def private_get_forbidden(task_id):
        raise AssertionError('vault ingress must use public registry.capture()')

    monkeypatch.setattr(browser_supervisor.SUPERVISOR_REGISTRY, 'get',
                        private_get_forbidden)
    return registry
