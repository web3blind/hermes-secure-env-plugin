"""Exact explicit-parent attachments on one original public captured connection.

Tab creation is irrelevant. Human/session authorization is enforced by callers;
this module never scans siblings, changes supervisor focus, or recaptures.
"""
from pathlib import Path
import threading
from urllib.parse import urlsplit

from .code_targets import _call
from .exact_card import _CardCDP


class ParentCDP(_CardCDP):
    """Frozen profile and human lease epoch, re-admitted at public before_send."""
    def __init__(self, raw, home):
        super().__init__(raw, home, raw.task_id)
        self.home, self.scope_guard = home, lambda: None

    def check(self):
        super().check()
        from hermes_constants import get_hermes_home
        if Path(get_hermes_home()).resolve() != self.home:
            raise ValueError('parent profile changed')
        self.scope_guard()


def _page_origin(info, parent):
    from agent.vault_store import normalize_origin
    from .vault_ingress import strict_origin
    url = info.get('url', '')
    parsed = urlsplit(url)
    if (info.get('targetId') != parent or info.get('type') != 'page'
            or parsed.scheme != 'https' or parsed.username or parsed.password):
        raise ValueError('parent unavailable')
    return strict_origin(normalize_origin(url))


class ParentSession:
    """Own only our attachment, never the tab or another actor's session."""
    def __init__(self, sup, parent):
        from hermes_constants import get_hermes_home
        if not isinstance(parent, str) or not 1 <= len(parent) <= 100:
            raise ValueError('invalid parent')
        self.sup, self.parent = sup, parent
        self.home = Path(get_hermes_home()).resolve()
        self.browser = sup.cdp_url
        self.transport = ParentCDP(sup, self.home)
        self.lock, self.refs, self.closed = threading.Lock(), {None}, False
        self.private, self.sid = True, None
        # Resolve ONLY the caller-selected existing target, on the original wire.
        info = _call(self.transport, 'Target.getTargetInfo', {'targetId': parent})['result']['targetInfo']
        self.origin = _page_origin(info, parent)
        self.sid = _call(self.transport, 'Target.attachToTarget',
                         {'targetId': parent, 'flatten': True})['result']['sessionId']
        try:
            self.check()
        except BaseException:
            self.drop(None)
            raise

    def check(self):
        from hermes_constants import get_hermes_home
        if (self.closed or not self.sup.is_valid()
                or Path(get_hermes_home()).resolve() != self.home):
            raise ValueError('parent connection changed')
        self.transport.check()
        info = _call(self.transport, 'Target.getTargetInfo', {}, self.sid)['result']['targetInfo']
        if _page_origin(info, self.parent) != self.origin:
            raise ValueError('parent session changed')
        return self.sid

    def keep(self, key):
        with self.lock:
            if self.closed:
                raise ValueError('parent session closed')
            self.refs.add(key)

    def drop(self, key):
        with self.lock:
            self.refs.discard(key)
            if self.refs or self.closed:
                return
            self.closed = True
            if self.sid:
                self.transport.dispose(self.sid, wait=True)
