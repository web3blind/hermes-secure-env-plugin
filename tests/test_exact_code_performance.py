"""Real retained 100-cell budget and sanitized transport-cost receipts."""
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path
from test_nested_code import nested as nested, setup_chain
from test_exact_code_browser import spec
from secure_env_ingress import code_targets as codes


def test_100_transport_budget(nested, monkeypatch):
    origin, leaf = setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+Array.from({length:100},(_,i)=>`<input id=c${i}>`).join("")+"</div>"')
    target = codes.discover(origin, 'Synthetic', nested.sup.task_id, parent=nested.parent, target_spec=spec(100, 'indexed_cells'))[0]
    original = target.supervisor._request
    counts, seconds = Counter(), defaultdict(float)
    def measured(method, params, sid, **kwargs):
        start = time.monotonic()
        try:
            return original(method, params, sid, **kwargs)
        finally:
            counts[method] += 1
            seconds[method] += time.monotonic()-start
    monkeypatch.setattr(target.supervisor, '_request', measured)
    start = time.monotonic()
    load = os.getloadavg()
    returned = False
    try:
        returned = codes.fill(target, '!'*100, start+120)
        assert returned
        assert leaf.evaluate('Array.from(document.querySelectorAll("input")).every(e=>e.value==="!")')
    finally:
        receipt = {'seconds':time.monotonic()-start,'returned':returned,'load_start':load,'load_end':os.getloadavg(),'calls':dict(counts),'call_seconds':dict(seconds),'writes':leaf.evaluate('Array.from(document.querySelectorAll("input")).filter(e=>e.value).length')}
        (Path.home()/'transport-cost.json').write_text(json.dumps(receipt,indent=2))
        print('TRANSPORT_COST '+json.dumps(receipt),flush=True)
        codes.release(target)
