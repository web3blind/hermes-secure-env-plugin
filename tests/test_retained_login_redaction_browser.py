"""Connected login with the modern native redaction keyword contract."""
from test_retained_login_browser import browser as _browser, env as _env, backend, registered

browser = _browser
env = _env


def test_native_secret_redaction_kind(env, monkeypatch):
    from agent import redact
    from gateway.run import _profile_runtime_scope
    original = redact.register_vault_redaction_value
    seen = []

    def modern(value, *, kind='secret'):
        if kind not in {'secret', 'otp', 'cvc'}:
            raise ValueError('unsupported redaction kind')
        seen.append(kind)
        original(value)

    monkeypatch.setattr(redact, 'register_vault_redaction_value', modern)
    handle, resolved = backend(env, monkeypatch)
    result = registered(env, monkeypatch, handle)
    assert result['status'] == 'filled', result
    assert seen == ['secret'] and len(resolved) == 1
    with _profile_runtime_scope(env.home, {}):
        sample = 'Synthetic-Long-Password!'
        assert sample not in redact.redact_registered_vault_values(sample)
    assert env.page.evaluate('window.writes===1&&!window.submitted')
