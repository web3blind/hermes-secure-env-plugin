"""Guard-to-census ordering for newly attached, unobserved shadow roots."""
import threading
import time
from types import SimpleNamespace

import pytest
from secure_env_ingress import bound_cdp as bc, nested_code as nc


class ShadowSchedule:
    task_id = 'synthetic'
    page_session_id = 'original-session'
    cdp_url = 'ws://synthetic'

    def __init__(self):
        self.census_taken = threading.Event()
        self.guard_done = threading.Event()
        self.shadow_created = False
        self.trace = []

    def is_valid(self):
        return True

    def call(self, method, params, *, session_id=None, timeout=None, before_send=None):
        if method == 'Runtime.callFunctionOn' and params['functionDeclaration'] == bc.GUARD_VALIDATION:
            # A mixed concurrent batch would let census overtake this guard.
            self.census_taken.wait(.05)
        before_send()
        if method == 'Runtime.callFunctionOn':
            function = params['functionDeclaration']
            if function == bc.GUARD_VALIDATION:
                self.shadow_created = True
                self.trace.append('guard:new-shadow')
                self.guard_done.set()
                return {'result': {'result': {'value': True}}}
            if function == 'function(n){return this.censusRoot(n)}':
                self.trace.append('censusRoot:refused')
                return {'result': {'result': {'value': False}}}
            raise AssertionError(function)
        if method == 'DOM.describeNode':
            if 'backendNodeId' in params:
                return {'result': {'node': {'nodeName': '#document-fragment', 'backendNodeId': 9,
                    'children': [{'nodeName': 'INPUT', 'backendNodeId': 10, 'attributes': ['name', 'otp']}]}}}
            observed = self.shadow_created
            self.trace.append('census:new-shadow' if observed else 'census:stale')
            root = {'nodeName': '#document', 'backendNodeId': 1, 'children': [
                {'nodeName': 'DIV', 'backendNodeId': 2, 'shadowRoots': [
                    {'nodeName': '#document-fragment', 'backendNodeId': 9,
                     'shadowRootType': 'closed'}] if observed else []}]}
            self.census_taken.set()
            assert self.guard_done.wait(2)
            return {'result': {'node': root}}
        if method == 'DOM.resolveNode':
            return {'result': {'object': {'objectId': 'new-root'}}}
        if method == 'Runtime.releaseObject':
            return {'result': {}}
        raise AssertionError(method)


def test_census_cannot_overtake_its_guard(monkeypatch):
    raw = ShadowSchedule()
    bound = bc.BoundCDP(raw)
    monkeypatch.setattr(nc, '_supervisor', lambda task: bound)
    target = SimpleNamespace(task='synthetic', supervisor=bound,
        expires=time.monotonic() + 30, parent='original-parent', parent_sid='original-session',
        ancestry=(), leaf_sid='original-session', leaf_guard='guard',
        lease=SimpleNamespace(closed=False, scopes=[], contexts={'guard': 42},
            census_documents={('original-session', 42): 'retained-document'},
            censuses={'guard': ((), ())},
            parent_session=SimpleNamespace(check=lambda: 'original-session')))
    with pytest.raises(ValueError, match='code document changed'):
        nc.assert_target(target)
    assert raw.trace == ['guard:new-shadow', 'census:new-shadow', 'censusRoot:refused']
    assert target.lease.censuses['guard'] == ((), ())
