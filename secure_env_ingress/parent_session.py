"""Exact private attachment for an explicitly requested, creation-owned page.

The host supervisor's default page is not Browser Use's selected page. A mismatch
may use a separate session, never change supervisor focus or infer ownership from
CDP visibility. Ownership authority is read-only and profile/browser-generation
bound. Existing already-attached pages keep their historical admission contract.
"""
from pathlib import Path
import threading
from urllib.parse import urlsplit

from .code_targets import _call, _supervisor
from .bound_cdp import BoundCDP


def _proof(task, browser, parent, home):
    from tools.browser_tab_lifecycle import Authority, readonly
    owner, generation = Authority(home).owner(task, task)
    if owner.startswith('unknown:'):
        raise ValueError('parent ownership unavailable')
    with readonly(home / 'browser_tabs.sqlite') as db:
        row = db.execute('SELECT t.call_token FROM targets t JOIN owners o USING(owner,generation) '
            'JOIN calls c ON c.token=t.call_token WHERE t.browser=? AND t.target=? '
            'AND t.owner=? AND t.generation=? AND o.terminal=0 AND t.pending_close=0 '
            'AND c.browser=t.browser AND c.owner=t.owner AND c.generation=t.generation '
            "AND c.state='drained'", (browser, parent, owner, generation)).fetchone()
    if row is None:
        raise ValueError('explicit parent not owned by task')
    return owner, generation, row['call_token']


class ParentSession:
    """Captured connection/session; never reattach a capability after reconnect."""
    def __init__(self, sup, parent):
        from hermes_constants import get_hermes_home
        if not isinstance(parent, str) or not 1 <= len(parent) <= 100:
            raise ValueError('invalid parent')
        self.sup, self.parent = sup, parent
        self.home = Path(get_hermes_home()).resolve()
        self.ws, self.loop, self.browser = sup._ws, sup._loop, sup.cdp_url
        self.transport = BoundCDP(sup)
        self.lock, self.refs, self.closed = threading.Lock(), {None}, False
        self.private, self.proof, self.sid = False, None, None
        sid = sup._page_session_id
        if sid and _call(self.transport, 'Target.getTargetInfo', {}, sid)['result']['targetInfo']['targetId'] == parent:
            self.sid = sid
        else:
            # Only pinned browser websockets, no endpoint discovery or new browser.
            url = urlsplit(self.browser)
            if url.scheme not in ('ws', 'wss') or not url.path.startswith('/devtools/browser/'):
                raise ValueError('browser generation unavailable')
            self.proof = _proof(sup.task_id, self.browser, parent, self.home)
            info = _call(self.transport, 'Target.getTargetInfo', {'targetId': parent})['result']['targetInfo']
            if info['targetId'] != parent or info['type'] != 'page' or urlsplit(info['url']).scheme != 'https':
                raise ValueError('parent unavailable')
            self.sid = _call(self.transport, 'Target.attachToTarget', {'targetId': parent, 'flatten': True})['result']['sessionId']
            self.private = True
        try:
            self.check()
        except BaseException:
            self.drop(None)
            raise

    def check(self):
        from hermes_constants import get_hermes_home
        sup = _supervisor(self.sup.task_id)
        if (self.closed or sup is not self.sup or sup._ws is not self.ws or sup._loop is not self.loop
                or sup.cdp_url != self.browser or Path(get_hermes_home()).resolve() != self.home):
            raise ValueError('parent connection changed')
        if self.private:
            if _proof(sup.task_id, self.browser, self.parent, self.home) != self.proof:
                raise ValueError('parent ownership changed')
        elif sup._page_session_id != self.sid:
            raise ValueError('parent attachment changed')
        info = _call(self.transport, 'Target.getTargetInfo', {}, self.sid)['result']['targetInfo']
        if info['targetId'] != self.parent or info['type'] != 'page':
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
            if self.private:
                self.transport.dispose(self.sid, wait=True)
