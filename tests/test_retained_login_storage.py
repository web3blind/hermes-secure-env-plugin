"""Storage-only reissuance through real HTTPS and native Vault, without a browser."""
from urllib.parse import urlsplit
import pytest
from test_runtime_e2e import make_runtime, post
from secure_env_ingress.vault_ingress import capture_login_target


@pytest.mark.parametrize('prior', ['cancel','expiry'])
def test_storage_reissue_remains_browser_independent(tmp_path, monkeypatch, prior):
    from secure_env_ingress import code_targets
    from agent.vault_store import VaultStore
    runtime,config,home,root=make_runtime(tmp_path,mini=False)
    monkeypatch.setenv('HERMES_HOME',str(home))
    def unavailable(*args,**kwargs):
        raise AssertionError('storage must not capture or require a browser')
    monkeypatch.setattr(code_targets,'_supervisor',unavailable)
    target=capture_login_target('https://author.test','Synthetic Author.Today storage','synthetic','key')
    try:
        first=runtime.create_vault(('telegram','7'),target)
        if prior=='cancel':
            runtime.cancel_group(first['group_id'])
        else:
            runtime._store.clear()  # Expire the exact pair without changing production TTL.
            with runtime._lock:
                runtime._stop_listener()
        assert first['completion'].result(timeout=2)['status']==('cancelled' if prior=='cancel' else 'expired')
        second=runtime.create_vault(('telegram','7'),target)
        status,result=post(config,root,'/submit',{'token':urlsplit(second['url']).fragment,
            'initData':'','values':['synthetic-reader','synthetic-storage-password']},timeout=20)
        assert (status,result)==(200,{'saved':True})
        outcome=second['completion'].result(timeout=2)
        assert outcome['status']=='saved' and outcome['origin']=='https://author.test'
        assert len(VaultStore(home/'vault').list_items())==1
        assert 'synthetic-storage-password' not in str(outcome)
        assert not (home/'browser_tabs.sqlite').exists()
    finally:
        runtime.close()
