"""Acceptance coverage for terminal submit semantics and user-visible outcomes."""
from __future__ import annotations

import json
import shutil
from typing import Any
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values

from secure_env_ingress.server import HTTPError
from test_runtime_e2e import make_runtime, post, signed_data

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - exercised only by minimal downstream installs
    sync_playwright = None


@pytest.fixture(scope="module")
def browser():
    """Use a disposable local Chromium; no external browser profile is touched."""
    if sync_playwright is None:
        pytest.skip("Playwright is not installed")
    executable = shutil.which("chromium") or shutil.which("chromium-browser")
    if executable is None:
        pytest.skip("Chromium is not installed")
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(
            executable_path=executable,
            headless=True,
            args=["--no-sandbox"],
        )
        yield instance
        instance.close()


def _page(browser: Any) -> tuple[Any, Any]:
    context = browser.new_context(ignore_https_errors=True)
    return context.new_page(), context


def _assert_consumed(runtime, token: str, init_data: str = "") -> None:
    with pytest.raises(HTTPError) as replay:
        runtime.session(token, init_data)
    assert replay.value.status == 410


def test_success_is_visible_and_submit_is_one_time(tmp_path, browser):
    runtime, _, home, _ = make_runtime(tmp_path)
    page, context = _page(browser)
    submissions: list[str] = []
    page.on(
        "request",
        lambda request: submissions.append(request.url)
        if urlsplit(request.url).path == "/submit"
        else None,
    )
    try:
        url = runtime.create(7, "service")["url"]
        token = urlsplit(url).fragment
        page.goto(url)
        assert page.title() == "Secure secret entry"
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.get_by_role("heading", name="Secure secret entry").is_visible()
        field = page.get_by_label("SERVICE_TOKEN", exact=True)
        field.fill("browser-lifecycle-fixture")
        page.get_by_role("button", name="Save").dblclick()

        status = page.get_by_role("status")
        status.get_by_text("Secrets saved", exact=False).wait_for()
        assert status.is_visible()
        assert field.input_value() == ""
        assert field.is_disabled()
        assert len(submissions) == 1
        assert dotenv_values(home / ".env", interpolate=False)["SERVICE_TOKEN"] == (
            "browser-lifecycle-fixture"
        )
        _assert_consumed(runtime, token)
    finally:
        context.close()
        runtime.close()


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param("", id="empty"),
        pytest.param("first\nsecond", id="multiline"),
        pytest.param("x" * 16385, id="oversize"),
    ],
)
def test_authenticated_invalid_submission_is_terminal(tmp_path, invalid_value):
    runtime, config, home, root = make_runtime(tmp_path)
    try:
        token = urlsplit(runtime.create(7, "service")["url"]).fragment
        status, _ = post(
            config,
            root,
            "/submit",
            {"token": token, "initData": "", "values": [invalid_value]},
        )

        assert status == 400
        assert not (home / ".env").exists()
        _assert_consumed(runtime, token)
    finally:
        runtime.close()


def test_write_failure_is_visible_and_terminal(tmp_path, browser):
    runtime, _, home, _ = make_runtime(tmp_path)
    target = home / ".env"
    target.write_text('SERVICE_TOKEN="existing-fixture"\n')
    target.chmod(0o600)
    before = target.read_bytes()
    page, context = _page(browser)
    try:
        url = runtime.create(7, "service")["url"]
        token = urlsplit(url).fragment
        page.goto(url)
        assert page.title() == "Secure secret entry"
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.get_by_role("heading", name="Secure secret entry").is_visible()
        field = page.get_by_label("SERVICE_TOKEN", exact=True)
        field.fill("must-not-replace-existing")
        page.get_by_role("button", name="Save").click()

        status = page.get_by_role("status")
        page.wait_for_function(
            "document.getElementById('status').textContent !== 'Saving…'"
        )
        message = status.inner_text().lower()
        assert status.is_visible()
        assert message.strip()
        assert "secrets saved" not in message
        assert "cleared" in message
        assert field.input_value() == ""
        assert field.is_disabled()
        assert target.read_bytes() == before
        _assert_consumed(runtime, token)
    finally:
        context.close()
        runtime.close()


def test_forged_mini_submission_does_not_consume_capability(tmp_path):
    runtime, config, home, root = make_runtime(tmp_path)
    try:
        token = urlsplit(runtime.create(7, "service")["web_app_url"]).fragment
        forged_status, _ = post(
            config,
            root,
            "/submit",
            {"token": token, "initData": signed_data(uid=8), "values": ["forged"]},
        )
        assert forged_status == 403
        assert not (home / ".env").exists()

        valid_init_data = signed_data()
        valid_status, result = post(
            config,
            root,
            "/submit",
            {
                "token": token,
                "initData": valid_init_data,
                "values": ["authenticated-fixture"],
            },
        )
        assert valid_status == 200
        assert result == {"added": ["SERVICE_TOKEN"]}
        assert dotenv_values(home / ".env", interpolate=False)["SERVICE_TOKEN"] == (
            "authenticated-fixture"
        )
        _assert_consumed(runtime, token, valid_init_data)
    finally:
        runtime.close()


def test_transport_loss_after_commit_reports_unknown_result(tmp_path, browser):
    runtime, config, home, root = make_runtime(tmp_path)
    page, context = _page(browser)
    committed: list[tuple[int, dict]] = []
    value = "committed-before-transport-loss"

    def commit_then_drop(route) -> None:
        payload = json.loads(route.request.post_data)
        committed.append(post(config, root, "/submit", payload))
        route.abort("connectionfailed")

    try:
        url = runtime.create(7, "service")["url"]
        token = urlsplit(url).fragment
        page.goto(url)
        page.route("**/submit", commit_then_drop)
        field = page.get_by_label("SERVICE_TOKEN", exact=True)
        field.fill(value)
        page.get_by_role("button", name="Save").click()

        status = page.get_by_role("status")
        page.wait_for_function(
            "document.getElementById('status').textContent !== 'Saving…'"
        )
        message = status.inner_text().lower()
        assert status.is_visible()
        assert "unknown" in message or "unconfirmed" in message
        assert "could not save" not in message
        assert "secrets saved" not in message
        assert field.input_value() == ""
        assert field.is_disabled()
        assert committed == [(200, {"added": ["SERVICE_TOKEN"]})]
        assert dotenv_values(home / ".env", interpolate=False)["SERVICE_TOKEN"] == value
        _assert_consumed(runtime, token)
    finally:
        context.close()
        runtime.close()
