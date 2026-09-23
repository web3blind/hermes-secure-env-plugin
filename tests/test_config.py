from __future__ import annotations

import os
from pathlib import Path

import pytest

from secure_env_ingress.config import ConfigError, IngressConfig, ProfileConfig


def _profile(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "target_mode": "hermes",
        "keys": ["SERVICE_TOKEN"],
    }
    data.update(overrides)
    return data


def _config(profiles: dict[str, object]) -> dict[str, object]:
    return {
        "public_ip": "203.0.113.10",
        "listen_host": "0.0.0.0",
        "listen_port": 18443,
        "cert_path": "/run/secure-env/fullchain.pem",
        "key_path": "/run/secure-env/privkey.pem",
        "safety_seconds": 86400,
        "ttl_seconds": 300,
        "allowed_telegram_user_ids": [7],
        "profiles": profiles,
    }


def test_strict_mapping_and_immutable_profile_data(tmp_path: Path) -> None:
    home = tmp_path / "home-a"
    home.mkdir(mode=0o700)
    raw = _config({"service": _profile(keys=["SERVICE_TOKEN", "OTHER_KEY"])})
    config = IngressConfig.from_mapping(raw)
    raw["profiles"]["service"]["keys"].append("MUTATED")  # type: ignore[index,union-attr]

    resolved = config.resolve("service", hermes_home=home, expected_uid=os.getuid())
    assert resolved.profile.name == "service"
    assert resolved.profile.keys == ("SERVICE_TOKEN", "OTHER_KEY")
    assert resolved.target.path == home / ".env"
    assert resolved.target.expected_uid == os.getuid()
    assert config.public_ip == "203.0.113.10"
    assert config.allowed_telegram_user_ids == frozenset({7})


@pytest.mark.parametrize(
    "raw",
    [
        {},
        _config({}),
        _config({"bad/name": _profile()}),
        _config({"setup": _profile()}),
        _config({"status": _profile()}),
        _config({"cancel": _profile()}),
        _config({"x": _profile(extra=True)}),
        _config({"x": _profile(keys=[])}),
        _config({"x": _profile(keys=["bad-name"])}),
        _config({"x": _profile(keys=["A", "A"])}),
        {**_config({"x": _profile()}), "ttl_seconds": 119},
        {**_config({"x": _profile()}), "ttl_seconds": 601},
        {**_config({"x": _profile()}), "ttl_seconds": True},
        _config({"x": _profile(target_mode="unknown")}),
        _config({"x": _profile(target_mode="hermes", target_path="/tmp/.env")}),
        {**_config({"x": _profile()}), "unknown": 1},
        {**_config({"x": _profile()}), "allowed_telegram_user_ids": []},
        {**_config({"x": _profile()}), "public_ip": "not-an-ip"},
        {**_config({"x": _profile()}), "cert_path": "relative.pem"},
    ],
)
def test_invalid_or_unknown_configuration_is_rejected(raw: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        IngressConfig.from_mapping(raw)


def test_non_hermes_targets_are_absolute_and_exact(tmp_path: Path) -> None:
    home = tmp_path / "home"
    target_parent = tmp_path / "project"
    home.mkdir(mode=0o700)
    target_parent.mkdir(mode=0o700)
    target = target_parent / ".env"
    config = IngressConfig.from_mapping(
        _config({"project-api": _profile(target_mode="project", target_path=str(target))})
    )
    resolved = config.resolve("project-api", hermes_home=home, expected_uid=os.getuid())
    assert resolved.target.path == target

    with pytest.raises(ConfigError):
        ProfileConfig.from_mapping(
            "relative", _profile(target_mode="custom", target_path="relative/.env")
        )


def test_profile_resolution_is_isolated_by_active_hermes_home(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    config = IngressConfig.from_mapping(_config({"service": _profile()}))

    a = config.resolve("service", hermes_home=first, expected_uid=os.getuid())
    b = config.resolve("service", hermes_home=second, expected_uid=os.getuid())
    assert a.target.path != b.target.path
    assert a.target.parent_identity != b.target.parent_identity


def test_hermes_home_must_be_absolute_existing_directory(tmp_path: Path) -> None:
    config = IngressConfig.from_mapping(_config({"service": _profile()}))
    with pytest.raises(ConfigError):
        config.resolve("service", hermes_home=Path("relative"), expected_uid=os.getuid())
    with pytest.raises(ConfigError):
        config.resolve("service", hermes_home=tmp_path / "missing", expected_uid=os.getuid())


def test_unknown_profile_is_rejected_without_name_suggestion(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    config = IngressConfig.from_mapping(_config({"service": _profile()}))
    with pytest.raises(ConfigError) as caught:
        config.resolve("absent", hermes_home=home, expected_uid=os.getuid())
    assert "service" not in str(caught.value)
