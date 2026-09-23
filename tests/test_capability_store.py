from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from secure_env_ingress.capability_store import (
    CapabilityStore,
    InvalidTTL,
)


class Clock:
    def __init__(self) -> None:
        self.now = 10_000.0

    def __call__(self) -> float:
        return self.now


def _issue(store: CapabilityStore, home: Path, *, user_id: int = 7, ttl: int = 300):
    return store.issue_pair(
        platform="telegram",
        user_id=user_id,
        hermes_home=home,
        profile_name="service",
        allowed_keys=("SERVICE_TOKEN",),
        target_id=(11, 22),
        ttl_seconds=ttl,
    )


def test_issues_256_bit_mode_bound_siblings_without_repr_leak(tmp_path: Path) -> None:
    store = CapabilityStore()
    browser, mini = _issue(store, tmp_path)

    assert browser.mode == "browser"
    assert mini.mode == "mini"
    assert browser.group_id == mini.group_id
    assert browser.token != mini.token
    assert len(browser.token) >= 43
    assert browser.token not in repr(browser)
    assert mini.token not in repr(mini)
    assert store.active_count == 2

    assert (
        store.consume(
            browser.token,
            mode="mini",
            platform="telegram",
            user_id=7,
            hermes_home=tmp_path,
        )
        is None
    )
    assert store.active_count == 2

    claim = store.consume(
        browser.token,
        mode="browser",
        platform="telegram",
        user_id=7,
        hermes_home=tmp_path,
    )
    assert claim is not None
    assert claim.profile_name == "service"
    assert claim.allowed_keys == ("SERVICE_TOKEN",)
    assert not hasattr(claim, "token")
    assert store.active_count == 0
    assert (
        store.consume(
            mini.token,
            mode="mini",
            platform="telegram",
            user_id=7,
            hermes_home=tmp_path,
        )
        is None
    )


def test_wrong_binding_does_not_consume(tmp_path: Path) -> None:
    store = CapabilityStore()
    browser, _ = _issue(store, tmp_path)
    attempts = [
        {"mode": "mini", "platform": "telegram", "user_id": 7, "hermes_home": tmp_path},
        {"mode": "browser", "platform": "other", "user_id": 7, "hermes_home": tmp_path},
        {"mode": "browser", "platform": "telegram", "user_id": 8, "hermes_home": tmp_path},
        {
            "mode": "browser",
            "platform": "telegram",
            "user_id": 7,
            "hermes_home": tmp_path / "other",
        },
    ]
    for attempt in attempts:
        assert store.consume(browser.token, **attempt) is None
    assert store.active_count == 2


def test_expiry_and_ttl_bounds(tmp_path: Path) -> None:
    clock = Clock()
    store = CapabilityStore(clock=clock)
    browser, _ = _issue(store, tmp_path, ttl=120)
    clock.now += 120
    assert (
        store.consume(
            browser.token,
            mode="browser",
            platform="telegram",
            user_id=7,
            hermes_home=tmp_path,
        )
        is None
    )
    assert store.active_count == 0

    for ttl in (119, 601, True):
        with pytest.raises(InvalidTTL):
            _issue(store, tmp_path, ttl=ttl)  # type: ignore[arg-type]


def test_new_request_cancels_prior_active_pair(tmp_path: Path) -> None:
    store = CapabilityStore()
    old_browser, old_mini = _issue(store, tmp_path)
    new_browser, _ = _issue(store, tmp_path)
    assert store.active_count == 2
    for issued in (old_browser, old_mini):
        assert (
            store.consume(
                issued.token,
                mode=issued.mode,
                platform="telegram",
                user_id=7,
                hermes_home=tmp_path,
            )
            is None
        )
    assert (
        store.consume(
            new_browser.token,
            mode="browser",
            platform="telegram",
            user_id=7,
            hermes_home=tmp_path,
        )
        is not None
    )


def test_cancel_is_context_bound_and_cancels_siblings(tmp_path: Path) -> None:
    store = CapabilityStore()
    browser, _ = _issue(store, tmp_path)
    assert not store.cancel(platform="telegram", user_id=8, hermes_home=tmp_path)
    assert store.active_count == 2
    assert store.cancel(platform="telegram", user_id=7, hermes_home=tmp_path)
    assert store.active_count == 0
    assert (
        store.consume(
            browser.token,
            mode="browser",
            platform="telegram",
            user_id=7,
            hermes_home=tmp_path,
        )
        is None
    )


def test_concurrent_consume_has_exactly_one_winner(tmp_path: Path) -> None:
    store = CapabilityStore()
    browser, _ = _issue(store, tmp_path)

    def consume() -> bool:
        return (
            store.consume(
                browser.token,
                mode="browser",
                platform="telegram",
                user_id=7,
                hermes_home=tmp_path,
            )
            is not None
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: consume(), range(32)))
    assert outcomes.count(True) == 1


def test_store_does_not_retain_plaintext_tokens(tmp_path: Path) -> None:
    store = CapabilityStore()
    browser, mini = _issue(store, tmp_path)
    state = repr(vars(store))
    assert browser.token not in state
    assert mini.token not in state
