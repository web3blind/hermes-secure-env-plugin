"""Synthetic clock crosses existing deadline at exact wire gates; no TTL change."""
import json,time
from types import SimpleNamespace
import pytest
from test_nested_code import nested,setup_chain
from test_exact_code_browser import spec
from acceptance_diagnostics import trace_fill

@pytest.mark.parametrize('phase',['revalidate','focus'])
def test_100_cell_expiry_keeps_identity_and_stops_writes(nested,phase,pytestconfig):
    from secure_env_ingress import code_targets as codes
    from secure_env_ingress.bound_cdp import fill_diagnostic_scope
    origin,leaf=setup_chain(nested)
    leaf.evaluate('document.body.innerHTML="<div id=group>"+Array.from({length:100},(_,i)=>`<div><input id=c${i} maxlength=1></div><span>decoration</span>`).join("")+"</div>"')
    target=codes.discover(origin,'Synthetic',nested.sup.task_id,parent=nested.parent,target_spec=spec(100,'indexed_cells',False))[0]
    evidence={}
    deadline=time.monotonic()+120
    try:
        with fill_diagnostic_scope() as state, trace_fill(target,deadline,evidence,expire_phase=phase):
            with pytest.raises(ValueError): codes.fill(target,'A'*100,deadline)
        count=leaf.evaluate('Array.from(document.querySelectorAll("input")).filter(e=>e.value.length>0).length')
        evidence['state']=dict(state)
        evidence['actual_writes']=count
        pytestconfig.cache.set('senv_acceptance_expiry/'+phase,evidence)
        refusal=evidence['wire']['refusals'][-1]
        assert refusal['phase']==phase and refusal['authorization_expired']
        assert refusal['captured_valid'] and refusal['profile_same'] and refusal['session_same']
        assert not refusal['cancelled'] and not refusal['lease_closed'] and not refusal['parent_closed']
        assert count==state['writes_confirmed']==2
        assert refusal['remaining']>0 and refusal['target_remaining']>0
    finally:
        codes.release(target)
