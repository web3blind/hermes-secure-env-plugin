"""Exact owner/generation/cancel/expiry and frozen true-origin human lease."""

import time
import pytest
from test_nested_code import nested as chromium_fixture
from exact_card_helpers import page, registered_fill

nested = chromium_fixture


@pytest.mark.parametrize(
    "change", ["cancel", "expiry", "generation", "lease", "lease_epoch"]
)
def test_terminal_before_resolve(nested, tmp_path, monkeypatch, change):
    from secure_env_ingress import exact_card as ec, payment_fill as pf
    from tools import browser_vault_tool as native

    captured = {}
    real_discover = ec.discover

    def discover(*a, **kw):
        targets = real_discover(*a, **kw)
        captured["target"] = targets[0]
        return targets

    monkeypatch.setattr(ec, "discover", discover)
    real_choose = pf.PaymentSelection.choose

    def choose(self, *a, **kw):
        captured["cancel"] = kw["batch"]
        return real_choose(self, *a, **kw)

    monkeypatch.setattr(pf.PaymentSelection, "choose", choose)
    if change.startswith("lease"):
        monkeypatch.setattr(native, "_bot_desktop_browser_session", lambda task: True)
    origin, leaf, s = page(nested)

    def mutate(_target):
        if change == "cancel":
            captured["cancel"].set()
        elif change == "expiry":
            object.__setattr__(captured["target"], "expires", time.monotonic() - 1)
        elif change == "generation":
            nested.sup.stop()
            nested.sup.start()
            nested.sup.focus_page("https://parent.test")
        else:
            from tools.bot_desktop import lease

            key = str(captured["target"].lease.parent_session.home)
            lease.acquire("synthetic-viewer", profile_key=key)
            if change == "lease_epoch":
                lease.release("synthetic-viewer", profile_key=key)

    result, seen, resolved = registered_fill(
        nested, tmp_path, monkeypatch, origin, s, mutation=mutate
    )
    assert result["status"] == "target_refused", result
    assert len(seen) == 1 and not resolved
    assert leaf.evaluate("window.writes===0&&!window.clicked&&!window.submitted")
    assert captured["target"].lease.closed


@pytest.mark.parametrize("proof", ["owned", "foreign", "retired"])
def test_registered_captured_original_parent(nested, tmp_path, monkeypatch, proof):
    from test_wrongsite_parent import authorize, wrongsite

    state = {}
    origin, leaf, s = page(nested, topology="nested")

    def setup(home):
        state["other"], state["sid"] = wrongsite(nested)
        ledger, token = authorize(
            tmp_path,
            monkeypatch,
            nested.sup,
            nested.parent,
            home=home,
            owner_task="foreign" if proof == "foreign" else None,
        )
        if proof == "retired":
            c = ledger.call(token)
            assert ledger.retire(c["owner"], c["generation"], evidence="synthetic-terminal")

    try:
        result, seen, resolved = registered_fill(
            nested, tmp_path, monkeypatch, origin, s, setup_hook=setup
        )
        assert result["status"] == (
            "filled" if proof == "owned" else "target_refused"
        ), result
        assert bool(seen) == bool(resolved) == (proof == "owned")
        assert nested.sup._page_session_id == state["sid"]
        assert leaf.evaluate("window.writes") == (4 if proof == "owned" else 0)
        assert leaf.evaluate("!window.clicked&&!window.submitted")
    finally:
        if "other" in state:
            state["other"].close()


def test_lease_rechecked_on_actual_secret_send(nested, tmp_path, monkeypatch):
    from tools import browser_vault_tool as native
    from tools.bot_desktop import lease

    monkeypatch.setattr(native, "_bot_desktop_browser_session", lambda task: True)
    origin, leaf, s = page(nested)
    capture_type = type(nested.capture())
    original = capture_type.call
    taken = []

    def request(self, method, params=None, *, session_id=None, timeout=10.0, before_send=None):
        kw = dict(session_id=session_id, timeout=timeout, before_send=before_send)
        if (method == "Runtime.callFunctionOn"
                and (params or {}).get("functionDeclaration")
                == "function(i,v){return this.write(i,v)}"):
            before_send = kw["before_send"]

            def acquire_on_dispatch():
                if not taken:
                    # Executed on the public host dispatch thread, not the
                    # plugin's worker-side final revalidation.
                    lease.acquire("synthetic-viewer", profile_key=taken_key[0])
                    taken.append(True)
                before_send()

            kw["before_send"] = acquire_on_dispatch
        return original(self, method, params, **kw)

    taken_key = []
    monkeypatch.setattr(capture_type, "call", request)
    result, _, resolved = registered_fill(
        nested,
        tmp_path,
        monkeypatch,
        origin,
        s,
        setup_hook=lambda h: taken_key.append(str(h)),
    )
    assert result["status"] == "unknown", result
    assert len(resolved) == 1 and taken
    assert leaf.evaluate("window.writes===0&&!window.clicked&&!window.submitted")
