"""Native provider metadata gates; resolution remains behind retained admission."""

from dataclasses import replace
from types import SimpleNamespace
import pytest
from agent.vault_store import VaultItemMeta
from secure_env_ingress.login_fill import login_backend


@pytest.mark.parametrize(
    "case", ["wrong_origin", "locked", "unavailable", "wrong_kind"]
)
def test_metadata_refusal_never_resolves_or_unlocks(monkeypatch, case):
    from agent import vault_backends

    calls = []
    meta = VaultItemMeta(
        "vault_synthetic", "login", "Synthetic", "https://a.test", "fixture"
    )
    if case == "wrong_kind":
        meta = replace(meta, kind="payment")
    if case == "wrong_handle":
        meta = replace(meta, id="vault_other")

    class Backend:
        needs_unlock = case == "locked"

        def is_unlocked(self):
            return False

        def get_meta(self, handle):
            calls.append("meta")
            return meta

        def resolve_password(self, handle):
            raise AssertionError("resolver must not be called")

        def resolve_otp(self, handle):
            raise AssertionError("resolver must not be called")

        def unlock(self, *args):
            raise AssertionError("unlock belongs to native protected surface")

    monkeypatch.setattr(
        vault_backends,
        "backend_for_handle",
        lambda handle: None if case == "unavailable" else Backend(),
    )
    with pytest.raises(ValueError):
        login_backend(
            "vault_synthetic",
            "https://b.test" if case == "wrong_origin" else "https://a.test",
        )
    if case in ("locked", "unavailable"):
        assert not calls


def test_manager_allowed_origins_are_exact_not_parent_or_wildcard(monkeypatch):
    from agent import vault_backends

    meta = VaultItemMeta(
        "op:synthetic",
        "login",
        "Synthetic",
        "https://a.test",
        "fixture",
        allowed_origins=("https://a.test", "https://b.test"),
    )
    backend = SimpleNamespace(needs_unlock=False, get_meta=lambda handle: meta)
    monkeypatch.setattr(vault_backends, "backend_for_handle", lambda handle: backend)
    assert login_backend("op:synthetic", "https://b.test") == (backend, meta)
    for origin in ("https://sub.b.test", "http://b.test", "https://b.test:444"):
        with pytest.raises(ValueError):
            login_backend("op:synthetic", origin)


def test_backend_metadata_identity_is_not_an_extra_gate(monkeypatch):
    from agent import vault_backends
    meta=VaultItemMeta("backend-record", "login", "Synthetic", "https://a.test", "fixture")
    backend=SimpleNamespace(needs_unlock=False,get_meta=lambda handle:meta)
    monkeypatch.setattr(vault_backends,"backend_for_handle",lambda handle:backend)
    assert login_backend("opaque-provider-handle","https://a.test")== (backend,meta)
