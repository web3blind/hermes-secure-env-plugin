"""Strict, immutable configuration and profile-aware target resolution."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .writer import InsecureTargetError, TargetBinding, bind_target

_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_PROFILES = frozenset({"setup", "status", "cancel"})
_TARGET_MODES = frozenset({"hermes", "skill", "project", "custom"})
_PROFILE_KEYS = frozenset({"target_mode", "target_path", "keys"})
_CONFIG_KEYS = frozenset(
    {
        "public_ip",
        "listen_host",
        "listen_port",
        "cert_path",
        "key_path",
        "safety_seconds",
        "ttl_seconds",
        "allowed_telegram_user_ids",
        "profiles",
        "mini_app_enabled",
    }
)
_REQUIRED_CONFIG_KEYS = _CONFIG_KEYS - {"mini_app_enabled"}


class ConfigError(ValueError):
    """Configuration is absent, malformed, or unsafe."""


def _strict_int(value: object, field: str, *, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ConfigError(f"invalid {field}")
    return value


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"invalid {field}")
    path = Path(value)
    if not path.is_absolute() or path.name in {"", ".", ".."} or ".." in path.parts:
        raise ConfigError(f"invalid {field}")
    return path


def _ipv4(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"invalid {field}")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ConfigError(f"invalid {field}") from None
    return str(address)


@dataclass(frozen=True, slots=True)
class ProfileConfig:
    name: str
    target_mode: str
    keys: tuple[str, ...]
    target_path: Path | None = None

    @classmethod
    def from_mapping(cls, name: str, raw: object) -> "ProfileConfig":
        if (
            not isinstance(name, str)
            or _PROFILE_RE.fullmatch(name) is None
            or name in _RESERVED_PROFILES
        ):
            raise ConfigError("invalid profile name")
        if not isinstance(raw, Mapping) or set(raw) - _PROFILE_KEYS:
            raise ConfigError("invalid profile configuration")

        mode = raw.get("target_mode")
        if not isinstance(mode, str) or mode not in _TARGET_MODES:
            raise ConfigError("invalid target_mode")

        raw_keys = raw.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise ConfigError("invalid profile keys")
        keys: list[str] = []
        for key in raw_keys:
            if not isinstance(key, str) or _KEY_RE.fullmatch(key) is None or key in keys:
                raise ConfigError("invalid profile keys")
            keys.append(key)

        if mode == "hermes":
            if "target_path" in raw:
                raise ConfigError("hermes targets cannot set target_path")
            target_path = None
        else:
            if "target_path" not in raw:
                raise ConfigError("non-hermes targets require target_path")
            target_path = _absolute_path(raw["target_path"], "target_path")

        return cls(name=name, target_mode=mode, keys=tuple(keys), target_path=target_path)


@dataclass(frozen=True, slots=True)
class ResolvedProfile:
    profile: ProfileConfig
    target: TargetBinding


@dataclass(frozen=True, slots=True)
class IngressConfig:
    public_ip: str
    listen_host: str
    listen_port: int
    cert_path: Path
    key_path: Path
    safety_seconds: int
    ttl_seconds: int
    allowed_telegram_user_ids: frozenset[int]
    profiles: Mapping[str, ProfileConfig]
    mini_app_enabled: bool = False

    @classmethod
    def from_mapping(cls, raw: object) -> "IngressConfig":
        if not isinstance(raw, Mapping):
            raise ConfigError("configuration must be a mapping")
        names = set(raw)
        if names - _CONFIG_KEYS or not _REQUIRED_CONFIG_KEYS.issubset(names):
            raise ConfigError("missing or unknown configuration fields")

        public_ip = _ipv4(raw["public_ip"], "public_ip")
        listen_host = _ipv4(raw["listen_host"], "listen_host")
        listen_port = _strict_int(raw["listen_port"], "listen_port", minimum=1, maximum=65535)
        cert_path = _absolute_path(raw["cert_path"], "cert_path")
        key_path = _absolute_path(raw["key_path"], "key_path")
        safety_seconds = _strict_int(raw["safety_seconds"], "safety_seconds", minimum=0)
        ttl_seconds = _strict_int(raw["ttl_seconds"], "ttl_seconds", minimum=120, maximum=600)

        raw_ids = raw["allowed_telegram_user_ids"]
        if not isinstance(raw_ids, list) or not raw_ids:
            raise ConfigError("allowed_telegram_user_ids must be a non-empty list")
        ids: set[int] = set()
        for user_id in raw_ids:
            parsed = _strict_int(user_id, "Telegram user id", minimum=1)
            if parsed in ids:
                raise ConfigError("duplicate Telegram user id")
            ids.add(parsed)

        raw_profiles = raw["profiles"]
        if not isinstance(raw_profiles, Mapping) or not raw_profiles:
            raise ConfigError("profiles must be a non-empty mapping")
        profiles: dict[str, ProfileConfig] = {}
        for name, profile_raw in raw_profiles.items():
            if not isinstance(name, str):
                raise ConfigError("invalid profile name")
            profile = ProfileConfig.from_mapping(name, profile_raw)
            profiles[name] = profile

        mini_app_enabled = raw.get("mini_app_enabled", False)
        if type(mini_app_enabled) is not bool:
            raise ConfigError("mini_app_enabled must be a boolean")

        return cls(
            public_ip=public_ip,
            listen_host=listen_host,
            listen_port=listen_port,
            cert_path=cert_path,
            key_path=key_path,
            safety_seconds=safety_seconds,
            ttl_seconds=ttl_seconds,
            allowed_telegram_user_ids=frozenset(ids),
            profiles=MappingProxyType(profiles),
            mini_app_enabled=mini_app_enabled,
        )

    def resolve(self, name: str, *, hermes_home: Path, expected_uid: int) -> ResolvedProfile:
        profile = self.profiles.get(name)
        if profile is None:
            # Do not disclose configured profile names in errors.
            raise ConfigError("unknown profile")
        if type(expected_uid) is not int or expected_uid < 0:
            raise ConfigError("invalid expected_uid")

        home = Path(hermes_home)
        if not home.is_absolute() or not home.is_dir():
            raise ConfigError("HERMES_HOME must be an absolute existing directory")
        target_path = home / ".env" if profile.target_mode == "hermes" else profile.target_path
        if target_path is None:
            raise ConfigError("missing target path")
        try:
            target = bind_target(target_path, expected_uid=expected_uid, create_parents=False)
        except (InsecureTargetError, OSError, ValueError) as exc:
            raise ConfigError("unsafe target") from exc
        return ResolvedProfile(profile=profile, target=target)
