"""Safe, non-privileged configuration CLI for Secure Environment Ingress.

This module only writes non-secret settings.  It never creates or reads a dotenv
value, and it deliberately does not provision certificates.
"""
from __future__ import annotations

import argparse
import copy
import errno
import fcntl
import importlib
import json
import os
import datetime as dt
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import yaml

from .config import ConfigError, IngressConfig, owner_identity
from .tls import TLSValidationError, validate_certificate
from .writer import InsecureTargetError, bind_target

PLUGIN_ID = "secure-env-ingress"
_DEFAULT_KEY = "SENV_TEST_VALUE"
_DEFAULT_PORT = 18443
_MAX_CONFIG_BYTES = 16 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_SECURITY_DEFAULTS = {
    "listen_host": "0.0.0.0",
    "safety_seconds": 86400,
    "ttl_seconds": 300,
    "mini_app_enabled": False,
}


class _StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise SetupConfigError("duplicate configuration key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class SetupConfigError(RuntimeError):
    """Configuration setup or verification failed closed."""


class UnauthorizedOwnerError(SetupConfigError):
    """The current on-disk configuration does not authorize this owner."""


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Value-free setup status suitable for CLI JSON output."""

    backup_created: bool = False
    changed: bool = False
    config_file_secure: bool = False
    config_valid: bool = False
    ready: bool = False
    target_safe: bool = False
    tls_valid: bool = False

    def as_dict(self) -> dict[str, bool]:
        return dict(sorted(asdict(self).items()))


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    """Value-free result of a named profile definition."""

    name: str
    keys: tuple[str, ...]
    target: Path


def _default_home() -> Path:
    try:
        get_hermes_home = importlib.import_module("hermes_constants").get_hermes_home
    except ImportError:
        configured = os.environ.get("HERMES_HOME", "").strip()
        return Path(configured).expanduser() if configured else Path.home() / ".hermes"
    return Path(get_hermes_home())


def _uid() -> int:
    if not hasattr(os, "geteuid"):
        raise SetupConfigError("this setup CLI requires POSIX filesystem security")
    uid = os.geteuid()
    if uid == 0:
        raise SetupConfigError("setup must run as a non-root user")
    return uid


def _absolute(path: str | os.PathLike[str] | Path, field: str) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute() or ".." in value.parts or value.name in {"", ".", ".."}:
        raise SetupConfigError(f"{field} must be an absolute path without traversal")
    return value


def _open_dir(path: Path) -> int:
    try:
        return os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise SetupConfigError("unsafe directory ancestry") from None
        raise


def _assert_private_dir(path: Path, uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SetupConfigError("cannot inspect private directory") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SetupConfigError("private directory must be a real directory")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise SetupConfigError("private directory must be owned by the runtime user with mode 0700")


def _ensure_absolute_dir(path: Path, uid: int, *, private_from: Path) -> None:
    """Descriptor-walk *path*, creating missing components without following links."""
    path = _absolute(path, "directory")
    private_from = _absolute(private_from, "private directory")
    try:
        path.relative_to(private_from)
    except ValueError as exc:
        raise SetupConfigError("private directory escapes the Hermes home") from exc

    fd = _open_dir(Path("/"))
    current = Path("/")
    try:
        for component in path.parts[1:]:
            current /= component
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                try:
                    child = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                        dir_fd=fd,
                    )
                except OSError as exc:
                    raise SetupConfigError("directory changed during private creation") from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise SetupConfigError("unsafe directory ancestry") from None
                raise
            os.close(fd)
            fd = child
            if current == private_from or private_from in current.parents:
                info = os.fstat(fd)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    raise SetupConfigError(
                        "private directory must be owned by the runtime user with mode 0700"
                    )
    finally:
        os.close(fd)


def _ensure_home(home: Path, uid: int) -> None:
    # The home itself is the security boundary. Existing parents may legitimately
    # be shared (for example /tmp in tests or /home on a host).
    _ensure_absolute_dir(home, uid, private_from=home)
    _assert_private_dir(home, uid)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_ctime_ns,
        info.st_mtime_ns,
        info.st_size,
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
        info.st_uid,
    )


def _validate_regular(info: os.stat_result, uid: int, label: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SetupConfigError(f"unsafe {label}: expected owned regular 0600 single-link file")


def _read_config_file(path: Path, uid: int) -> tuple[dict, bytes | None, tuple[int, ...] | None]:
    flags = os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW | _CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return {}, None, None
    except OSError as exc:
        raise SetupConfigError("unsafe config file") from exc
    try:
        info = os.fstat(fd)
        _validate_regular(info, uid, "config file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise SetupConfigError("existing config is too large")
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        loaded = yaml.load(raw.decode("utf-8"), Loader=_StrictLoader) if raw else {}
    except (UnicodeDecodeError, yaml.YAMLError, TypeError, ValueError) as exc:
        raise SetupConfigError("existing config is malformed") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise SetupConfigError("existing config is malformed")
    return loaded, raw, _file_identity(info)


def _current_identity(path: Path, uid: int) -> tuple[int, ...] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SetupConfigError("cannot inspect config file") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SetupConfigError("unsafe config file")
    _validate_regular(info, uid, "config file")
    return _file_identity(info)


@contextmanager
def _config_lock(home: Path, uid: int) -> Iterator[None]:
    lock_path = home / ".config.yaml.secure-env.lock"
    flags = os.O_RDWR | os.O_CREAT | _NOFOLLOW | _CLOEXEC
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise SetupConfigError("cannot acquire configuration lock") from exc
    try:
        _validate_regular(os.fstat(fd), uid, "configuration lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SetupConfigError("configuration write failed")
        view = view[written:]


def _private_backup(home: Path, source: bytes, uid: int) -> None:
    backup_dir = home / "secrets-ingress" / "config-backups"
    _ensure_absolute_dir(backup_dir, uid, private_from=home)
    name = f"config.yaml.secure-env-setup.{time.time_ns()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
    try:
        fd = os.open(backup_dir / name, flags, 0o600)
        try:
            _validate_regular(os.fstat(fd), uid, "configuration backup")
            _write_all(fd, source)
            os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = _open_dir(backup_dir)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise SetupConfigError("private configuration backup failed") from exc


def _atomic_write(path: Path, data: dict, uid: int, expected_identity: tuple[int, ...] | None) -> None:
    """Delegate persistence to Hermes' canonical, comment-preserving writer."""
    from hermes_cli.config import require_readable_config_before_write
    from utils import atomic_roundtrip_yaml_save
    if _current_identity(path, uid) != expected_identity:
        raise SetupConfigError("config file changed during setup")
    try:
        require_readable_config_before_write(path)
        atomic_roundtrip_yaml_save(path, data)
        # Some Hermes releases create config.yaml as 0644. The checked 0700
        # profile directory keeps it private while we tighten the new inode.
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid:
                raise SetupConfigError("unsafe written config file")
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        raise SetupConfigError("canonical configuration write failed") from None


def _same_value(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _requested_settings(
    *, home: Path, owner: int | tuple[str, str], public_ip: str, profile: str, keys: Sequence[str],
    tls_dir: Path | None, port: int,
) -> tuple[dict[str, object], Path, Path]:
    if type(owner) is int and owner > 0:
        owner_settings = {"allowed_telegram_user_ids": [owner]}
    elif isinstance(owner, tuple) and len(owner) == 2 and owner_identity(*owner) == owner:
        owner_settings = {"allowed_owners": {owner[0]: [owner[1]]}}
    else:
        raise SetupConfigError("owner must be a valid platform and exact user ID")
    if isinstance(port, bool) or not isinstance(port, int):
        raise SetupConfigError("port must be an integer")
    key_names = list(keys)
    target = home / "secrets-ingress" / f"{profile}.env"
    certificate_dir = tls_dir or home / "secrets-ingress" / "tls" / "current"
    certificate_dir = _absolute(certificate_dir, "TLS directory")
    requested: dict[str, object] = {
        "public_ip": public_ip,
        "listen_host": _SECURITY_DEFAULTS["listen_host"],
        "listen_port": port,
        "cert_path": str(certificate_dir / "fullchain.pem"),
        "key_path": str(certificate_dir / "privkey.pem"),
        "safety_seconds": _SECURITY_DEFAULTS["safety_seconds"],
        "ttl_seconds": _SECURITY_DEFAULTS["ttl_seconds"],
        **owner_settings,
        "profiles": {
            profile: {
                "target_mode": "custom",
                "target_path": str(target),
                "keys": key_names,
            }
        },
        "mini_app_enabled": _SECURITY_DEFAULTS["mini_app_enabled"],
    }
    try:
        IngressConfig.from_mapping(requested)
    except ConfigError as exc:
        raise SetupConfigError("requested ingress configuration is invalid") from exc
    return requested, target, certificate_dir


def _merge(raw: dict, requested: dict[str, object], profile: str) -> dict:
    merged = copy.deepcopy(raw)
    plugins = merged.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        raise SetupConfigError("existing plugins configuration is malformed")
    enabled = plugins.setdefault("enabled", [])
    if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
        raise SetupConfigError("existing plugin enablement is malformed")
    if PLUGIN_ID not in enabled:
        enabled.append(PLUGIN_ID)
    entries = plugins.setdefault("entries", {})
    if not isinstance(entries, dict):
        raise SetupConfigError("existing plugin entries are malformed")
    entry = entries.setdefault(PLUGIN_ID, {})
    if not isinstance(entry, dict):
        raise SetupConfigError("existing secure environment plugin entry is malformed")
    settings = entry.setdefault("settings", {})
    if not isinstance(settings, dict):
        raise SetupConfigError("existing secure environment settings are malformed")

    for name in (
        "public_ip", "listen_host", "listen_port", "cert_path", "key_path",
        "safety_seconds", "ttl_seconds", "mini_app_enabled",
    ):
        expected = requested[name]
        if name in settings and not _same_value(settings[name], expected):
            raise SetupConfigError(f"conflicting existing security setting: {name}")
        settings[name] = copy.deepcopy(expected)

    if "allowed_telegram_user_ids" in requested:
        current_ids = settings.setdefault("allowed_telegram_user_ids", [])
        if not isinstance(current_ids, list):
            raise SetupConfigError("existing Telegram allowlist is malformed")
        owner = requested["allowed_telegram_user_ids"][0]  # type: ignore[index]
        if owner not in current_ids:
            current_ids.append(owner)
    else:
        requested_owners = requested["allowed_owners"]
        platform, ids = next(iter(requested_owners.items()))
        owners = settings.setdefault("allowed_owners", {})
        if not isinstance(owners, dict):
            raise SetupConfigError("existing owner allowlist is malformed")
        current_ids = owners.setdefault(platform, [])
        if not isinstance(current_ids, list):
            raise SetupConfigError("existing owner allowlist is malformed")
        if ids[0] not in current_ids:
            current_ids.append(ids[0])

    profiles = settings.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        raise SetupConfigError("existing profiles configuration is malformed")
    requested_profile = requested["profiles"][profile]  # type: ignore[index]
    if profile in profiles and profiles[profile] != requested_profile:
        raise SetupConfigError("existing profile conflicts with the requested profile")
    profiles.setdefault(profile, copy.deepcopy(requested_profile))

    try:
        IngressConfig.from_mapping(settings)
    except ConfigError as exc:
        raise SetupConfigError("existing secure environment settings are malformed") from exc
    return merged


def _extract_settings(raw: Mapping[str, object]) -> object:
    try:
        return raw["plugins"]["entries"][PLUGIN_ID]["settings"]  # type: ignore[index]
    except (KeyError, TypeError):
        return None


def _config_matches(raw: dict, requested: dict[str, object], profile: str) -> bool:
    settings = _extract_settings(raw)
    if not isinstance(settings, Mapping):
        return False
    try:
        IngressConfig.from_mapping(settings)
        enabled = raw["plugins"]["enabled"]  # type: ignore[index]
        if not isinstance(enabled, list) or PLUGIN_ID not in enabled:
            return False
        for name in (
            "public_ip", "listen_host", "listen_port", "cert_path", "key_path",
            "safety_seconds", "ttl_seconds", "mini_app_enabled",
        ):
            if name not in settings or not _same_value(settings[name], requested[name]):
                return False
        from .config import configured_owners
        owner_allowed = configured_owners(requested).issubset(configured_owners(settings))
        profiles = settings["profiles"]
        return (
            owner_allowed
            and isinstance(profiles, Mapping)
            and profiles.get(profile) == requested["profiles"][profile]  # type: ignore[index]
        )
    except (ConfigError, KeyError, TypeError):
        return False


def _target_is_safe(target: Path, uid: int) -> bool:
    try:
        binding = bind_target(target, expected_uid=uid, create_parents=False)
    except (InsecureTargetError, OSError, ValueError):
        return False
    del binding
    return True


def _tls_is_valid(settings: Mapping[str, object], public_ip: str, uid: int) -> bool:
    try:
        validate_certificate(
            str(settings["cert_path"]),
            str(settings["key_path"]),
            expected_ip=public_ip,
            owner_uid=uid,
            minimum_remaining=dt.timedelta(seconds=int(settings["safety_seconds"])),
        )
    except (KeyError, TypeError, OSError, TLSValidationError):
        return False
    return True


def _verify(
    *, home: Path, requested: dict[str, object], target: Path, profile: str,
    uid: int, changed: bool = False, backup_created: bool = False,
) -> VerificationReport:
    config_path = home / "config.yaml"
    try:
        raw, _bytes, _identity = _read_config_file(config_path, uid)
        config_file_secure = True
    except SetupConfigError:
        return VerificationReport(changed=changed, backup_created=backup_created)
    config_valid = _config_matches(raw, requested, profile)
    target_safe = _target_is_safe(target, uid)
    settings = _extract_settings(raw)
    tls_valid = (
        _tls_is_valid(settings, str(requested["public_ip"]), uid)
        if config_valid and isinstance(settings, Mapping)
        else False
    )
    ready = config_file_secure and config_valid and target_safe and tls_valid
    return VerificationReport(
        backup_created=backup_created,
        changed=changed,
        config_file_secure=config_file_secure,
        config_valid=config_valid,
        ready=ready,
        target_safe=target_safe,
        tls_valid=tls_valid,
    )


def configure(
    *, home: str | os.PathLike[str] | Path | None = None, owner: int | tuple[str, str],
    public_ip: str, profile: str = "test", keys: Sequence[str] = (_DEFAULT_KEY,),
    tls_dir: str | os.PathLike[str] | Path | None = None, port: int = _DEFAULT_PORT,
) -> VerificationReport:
    """Merge ingress settings into one profile config without touching secret files."""
    uid = _uid()
    selected_home = _absolute(home if home is not None else _default_home(), "Hermes home")
    selected_tls = _absolute(tls_dir, "TLS directory") if tls_dir is not None else None
    requested, target, certificate_dir = _requested_settings(
        home=selected_home, owner=owner, public_ip=public_ip, profile=profile,
        keys=keys, tls_dir=selected_tls, port=port,
    )
    _ensure_home(selected_home, uid)
    _ensure_absolute_dir(target.parent, uid, private_from=selected_home)
    # Create only the stable TLS parent. The audited deploy helper owns the
    # generation and `current` symlink; setup must not pre-empt it with a dir.
    tls_parent = certificate_dir.parent
    if selected_home == tls_parent or selected_home in tls_parent.parents:
        _ensure_absolute_dir(tls_parent, uid, private_from=selected_home)

    config_path = selected_home / "config.yaml"
    with _config_lock(selected_home, uid):
        raw, original_bytes, identity = _read_config_file(config_path, uid)
        merged = _merge(raw, requested, profile)
        # Validate the destination before any config backup or mutation. This
        # only inspects metadata; secret values are never read by setup.
        if not _target_is_safe(target, uid):
            raise SetupConfigError("unsafe ingress target")
        changed = raw != merged
        backup_created = False
        if changed:
            if original_bytes is not None:
                _private_backup(selected_home, original_bytes, uid)
                backup_created = True
                if _current_identity(config_path, uid) != identity:
                    raise SetupConfigError("config file changed before mutation")
            _atomic_write(config_path, merged, uid, identity)

    report = _verify(
        home=selected_home, requested=requested, target=target, profile=profile,
        uid=uid, changed=changed, backup_created=backup_created,
    )
    if not report.config_file_secure or not report.config_valid or not report.target_safe:
        raise SetupConfigError("configuration read-back verification failed")
    return report


def define_named_profile(
    *, home: str | os.PathLike[str] | Path | None = None, owner: int | tuple[str, str],
    profile: str, keys: Sequence[str],
) -> ProfileDefinition:
    """Define fields for an authorized owner without reading or writing secret values."""
    uid = _uid()
    selected_home = _absolute(home if home is not None else _default_home(), "Hermes home")
    _assert_private_dir(selected_home, uid)
    config_path = selected_home / "config.yaml"

    with _config_lock(selected_home, uid):
        raw, original_bytes, identity = _read_config_file(config_path, uid)
        if original_bytes is None:
            raise SetupConfigError("secure ingress is not configured; use /senv setup")
        current_settings = _extract_settings(raw)
        try:
            current = IngressConfig.from_mapping(current_settings)
        except ConfigError as exc:
            raise SetupConfigError("existing secure environment settings are malformed") from exc
        authorized_owner = ('telegram', str(owner)) if type(owner) is int else owner
        if (not isinstance(authorized_owner, tuple) or len(authorized_owner) != 2
                or owner_identity(*authorized_owner) != authorized_owner or authorized_owner not in current.owners):
            raise UnauthorizedOwnerError("owner is not authorized")

        key_names = list(keys)
        existing = current.profiles.get(profile)
        if existing is None:
            target = selected_home / "secrets-ingress" / f"{profile}.env"
            profile_mapping: dict[str, object] = {
                "target_mode": "custom",
                "target_path": str(target),
                "keys": key_names,
            }
        else:
            target = selected_home / ".env" if existing.target_mode == "hermes" else existing.target_path
            if target is None:
                raise SetupConfigError("existing profile target is malformed")
            profile_mapping = {
                "target_mode": existing.target_mode,
                "keys": key_names,
            }
            if existing.target_mode != "hermes":
                profile_mapping["target_path"] = str(target)

        # Validate names, exact key spelling, and destination before backup/write.
        from .config import ProfileConfig
        try:
            ProfileConfig.from_mapping(profile, profile_mapping)
            if existing is None:
                _ensure_absolute_dir(target.parent, uid, private_from=selected_home)
            binding = bind_target(target, expected_uid=uid, create_parents=False)
        except (ConfigError, InsecureTargetError, OSError, ValueError) as exc:
            raise SetupConfigError("requested profile definition is invalid or unsafe") from exc
        del binding

        merged = copy.deepcopy(raw)
        settings = _extract_settings(merged)
        if not isinstance(settings, dict):
            raise SetupConfigError("existing secure environment settings are malformed")
        profiles = settings.get("profiles")
        if not isinstance(profiles, dict):
            raise SetupConfigError("existing profiles configuration is malformed")
        profiles[profile] = profile_mapping
        try:
            verified = IngressConfig.from_mapping(settings)
        except ConfigError as exc:
            raise SetupConfigError("updated secure environment settings are invalid") from exc
        if authorized_owner not in verified.owners:
            raise UnauthorizedOwnerError("owner is not authorized")

        if raw != merged:
            _private_backup(selected_home, original_bytes, uid)
            if _current_identity(config_path, uid) != identity:
                raise SetupConfigError("config file changed before mutation")
            _atomic_write(config_path, merged, uid, identity)

        readback, _bytes, _readback_identity = _read_config_file(config_path, uid)
        readback_settings = _extract_settings(readback)
        try:
            final = IngressConfig.from_mapping(readback_settings)
            final_profile = final.profiles[profile]
        except (ConfigError, KeyError) as exc:
            raise SetupConfigError("configuration read-back verification failed") from exc
        final_target = selected_home / ".env" if final_profile.target_mode == "hermes" else final_profile.target_path
        if final_profile.keys != tuple(key_names) or final_target != target:
            raise SetupConfigError("configuration read-back verification failed")

    return ProfileDefinition(name=profile, keys=tuple(key_names), target=target)


def check_configuration(
    *, home: str | os.PathLike[str] | Path | None = None, owner: int | tuple[str, str],
    public_ip: str, profile: str = "test", keys: Sequence[str] = (_DEFAULT_KEY,),
    tls_dir: str | os.PathLike[str] | Path | None = None, port: int = _DEFAULT_PORT,
) -> VerificationReport:
    """Read back configuration, target metadata, and TLS readiness without mutation."""
    uid = _uid()
    selected_home = _absolute(home if home is not None else _default_home(), "Hermes home")
    _assert_private_dir(selected_home, uid)
    selected_tls = _absolute(tls_dir, "TLS directory") if tls_dir is not None else None
    requested, target, _certificate_dir = _requested_settings(
        home=selected_home, owner=owner, public_ip=public_ip, profile=profile,
        keys=keys, tls_dir=selected_tls, port=port,
    )
    return _verify(home=selected_home, requested=requested, target=target, profile=profile, uid=uid)


def _positive_owner(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("owner must be a positive numeric Telegram ID")
    parsed = int(value, 10)
    if parsed < 1:
        raise argparse.ArgumentTypeError("owner must be a positive numeric Telegram ID")
    return parsed


def _port(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Configure or verify Secure Environment Ingress")
    parser.add_argument("mode", choices=("configure", "check"))
    parser.add_argument("--home", type=Path, default=None, help="active Hermes profile home")
    parser.add_argument("--owner", required=True, help="exact platform user ID (numeric for Telegram)")
    parser.add_argument("--platform", "--owner-platform", dest="owner_platform", default="telegram", help="gateway platform name")
    parser.add_argument("--public-ip", required=True, help="public IPv4 address")
    parser.add_argument("--profile", default="test", help="ingress profile name")
    parser.add_argument("--keys", nargs="+", default=[_DEFAULT_KEY], help="environment key names only")
    parser.add_argument("--tls-dir", type=Path, default=None, help="directory containing TLS files")
    parser.add_argument("--port", type=_port, default=_DEFAULT_PORT, help="HTTPS listen port")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    operation = configure if args.mode == "configure" else check_configuration
    try:
        owner = (_positive_owner(args.owner) if args.owner_platform == 'telegram'
                 else (args.owner_platform, args.owner))
        report = operation(
            home=args.home,
            owner=owner,
            public_ip=args.public_ip,
            profile=args.profile,
            keys=args.keys,
            tls_dir=args.tls_dir,
            port=args.port,
        )
    except (SetupConfigError, argparse.ArgumentTypeError) as exc:
        print(f"setup configuration refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), sort_keys=True))
    if args.mode == "check" and not report.ready:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
