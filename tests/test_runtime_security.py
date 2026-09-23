import hashlib
import os
from urllib.parse import urlsplit
import pytest
from secure_env_ingress.runtime import IngressRuntime
from secure_env_ingress.server import HTTPError
from secure_env_ingress.writer import bind_target
from test_runtime_e2e import make_runtime, post


def test_mixed_existing_keys_refuses_before_any_mutation(tmp_path):
    sample, settings, home, root = make_runtime(tmp_path)
    sample.close()
    settings['profiles']['service']['keys'] = ['EXISTING', 'MISSING']
    target = home / '.env'
    target.write_text('EXISTING="fixture-old"\n')
    target.chmod(0o600)
    before = hashlib.sha256(target.read_bytes()).digest()
    runtime = IngressRuntime(settings, home, 'fixture-bot', trust_roots=root)
    try:
        token = urlsplit(runtime.create(7, 'service')['url']).fragment
        status, _ = post(settings, root, '/submit', {'token': token, 'initData': '', 'values': ['new-fixture', 'other-fixture']})
        assert status == 409
        assert hashlib.sha256(target.read_bytes()).digest() == before
        with pytest.raises(HTTPError) as failure:
            runtime.session(token, '')
        assert failure.value.status == 410
    finally:
        runtime.close()


def test_target_fingerprints_include_exact_path(tmp_path):
    a = bind_target(tmp_path / 'a.env', expected_uid=os.getuid())
    b = bind_target(tmp_path / 'b.env', expected_uid=os.getuid())
    assert a.parent_identity == b.parent_identity
    assert IngressRuntime._target_id(a) != IngressRuntime._target_id(b)


def test_store_consume_checks_complete_binding(tmp_path):
    runtime, _, _, _ = make_runtime(tmp_path)
    try:
        token = urlsplit(runtime.create(7, 'service')['url']).fragment
        claim = runtime._store.peek(token)
        args = dict(mode=claim.mode, platform=claim.platform, user_id=claim.user_id,
                    hermes_home=runtime.home, profile_name=claim.profile_name,
                    target_id=claim.target_id, allowed_keys=claim.allowed_keys)
        for wrong in ({'target_id': (0, 0)}, {'profile_name': 'other'}, {'allowed_keys': ('OTHER',)}):
            assert runtime._store.consume(token, **(args | wrong)) is None
        assert runtime._store.consume(token, **args) is not None
    finally:
        runtime.close()
