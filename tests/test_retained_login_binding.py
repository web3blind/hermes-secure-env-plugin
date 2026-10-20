"""Static session-binding diagnostics, no contextual identifiers or secrets."""

import json
import pytest
from gateway import session_context as sc
from gateway.run import _profile_runtime_scope
from generic_helpers import registered
from test_runtime_e2e import make_runtime
from tools.registry import registry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "detail",
    [
        "request",
        "plugin_inactive",
        "interactive_context",
        "delegation",
        "session_identity",
        "owner_identity",
        "destination_identity",
        "profile_identity",
    ],
)
async def test_denied_details(tmp_path, monkeypatch, detail):
    from agent import delegation_context

    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv("HERMES_HOME", str(home))
    args = {"origin": "https://a.test", "label": "Synthetic"}
    variables = dict(
        platform="telegram",
        cron_session="",
        session_id="synthetic",
        session_key="synthetic",
        user_id="7",
        chat_id="7",
        chat_type="dm",
        profile="",
    )
    if detail == "request":
        args = {}
    if detail == "interactive_context":
        variables["platform"] = "discord"
    if detail == "delegation":
        monkeypatch.setattr(
            delegation_context, "is_delegated_child_context", lambda: True
        )
    if detail == "session_identity":
        variables["session_key"] = ""
    if detail == "owner_identity":
        variables["user_id"] = "999"
    if detail == "destination_identity":
        variables["chat_id"] = "not-a-numeric-destination"
    if detail == "profile_identity":
        variables["profile"] = "another-profile"
    tokens = sc.set_session_vars(**variables)
    try:
        with (
            registered(monkeypatch, home, settings=settings) as (manager, _),
            _profile_runtime_scope(home, {}),
        ):
            handler = registry.get_entry("secure_env_vault").handler
            if detail == "plugin_inactive":
                manager.unload()
            result = json.loads(
                await handler(args, task_id="synthetic", session_id="synthetic")
            )
            assert result["reason"] == "session_binding", result
            assert result["detail"] == detail, result
            assert result["success"] is False
            assert all(
                v not in json.dumps(result)
                for v in ["999", "another-profile", "not-a-numeric-destination"]
            )
    finally:
        sc.clear_session_vars(tokens)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing_parent", "capture_unavailable"])
async def test_code_browser_capability_refusal_precedes_prompt(
    tmp_path, monkeypatch, case
):
    from secure_env_ingress import code_targets

    runtime, settings, home, _ = make_runtime(tmp_path, mini=False)
    runtime.close()
    monkeypatch.setenv("HERMES_HOME", str(home))
    called = []

    def capture(task):
        called.append(True)
        raise ValueError("public browser capture unavailable")

    monkeypatch.setattr(code_targets, "_supervisor", capture)
    args = {"origin": "https://a.test", "label": "Synthetic", "mode": "code"}
    if case == "capture_unavailable":
        args["parent"] = "exact-existing-parent"
    tokens = sc.set_session_vars(
        platform="telegram",
        cron_session="",
        session_id="synthetic",
        session_key="synthetic",
        user_id="7",
        chat_id="7",
        chat_type="dm",
    )
    try:
        with (
            registered(monkeypatch, home, settings=settings) as (_, runner),
            _profile_runtime_scope(home, {}),
        ):
            result = json.loads(
                await registry.get_entry("secure_env_vault").handler(
                    args, task_id="synthetic", session_id="synthetic"
                )
            )
            assert result["reason"] == "browser_binding", result
            assert result["detail"] == (
                "parent_binding" if case == "missing_parent" else "browser_unavailable"
            ), result
            assert bool(called) == (case == "capture_unavailable")
            assert not runner.sent
    finally:
        sc.clear_session_vars(tokens)
