"""Administrator-installed, in-process consumers for ephemeral HTTPS secrets.

This is a trust boundary, not a sandbox. Never register model-generated code.
"""
from dataclasses import dataclass, field
import json
import inspect
import hashlib
import os
import re
import stat
import threading
import types
from pathlib import Path
from typing import Callable

_NAME = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
_LOCK = threading.RLock()
_CONSUMERS = {}


@dataclass(frozen=True)
class BoundOperation:
    """Factory-produced snapshot: trusted code owns its closure and side effects.

    execute receives the ephemeral password exactly once. It must not return data
    to the agent: its return value is ignored. Exceptions are never displayed.
    """
    summary: str
    execute: Callable[[str], object] = field(repr=False)


def register_consumer(home: Path, name: str, factory: Callable[[bytes], BoundOperation],
                      *, requires_verified_principal: bool = False) -> None:
    """Call only from trusted administrator-installed code at plugin startup.

    Factory receives canonical UTF-8 JSON bytes, validates all public parameters,
    freezes its target/operation inside a closure and returns a plain-text summary.
    This registry never imports paths or resolves commands from agent arguments.
    """
    if (not isinstance(name, str) or not _NAME.fullmatch(name) or not callable(factory)
            or type(requires_verified_principal) is not bool):
        raise ValueError('invalid consumer registration')
    key = (Path(home).absolute(), name)
    with _LOCK:
        if key in _CONSUMERS:
            raise ValueError('consumer already registered')
        _CONSUMERS[key] = (factory, requires_verified_principal)


def bind(home: Path, name: str, parameters: object) -> tuple[BoundOperation, bytes]:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError('invalid consumer')
    with _LOCK:
        entry = _CONSUMERS.get((Path(home).absolute(), name))
    if entry is None or entry[1]:
        # Verified Telegram Mini App delivery is not currently available here.
        # Never silently downgrade to bearer-only authorization.
        raise ValueError('consumer unavailable')
    canonical = json.dumps(parameters, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(canonical) > 4096 or not isinstance(parameters, dict):
        raise ValueError('invalid parameters')
    bound = entry[0](canonical)
    if (type(bound) is not BoundOperation or not callable(bound.execute)
            or inspect.iscoroutinefunction(bound.execute)
            or not isinstance(bound.summary, str) or not bound.summary.strip()
            or len(bound.summary.encode('utf-8')) > 768
            or any(ord(char) < 32 or ord(char) == 127 for char in bound.summary)):
        raise ValueError('invalid bound operation')
    return bound, canonical


def clear_consumers(home: Path) -> None:
    """Revoke registrations on plugin unload (including profile reload)."""
    selected = Path(home).absolute()
    with _LOCK:
        for key in list(_CONSUMERS):
            if key[0] == selected:
                del _CONSUMERS[key]


def load_configured_consumers(home: Path, raw: object) -> None:
    """Load an admin-pinned, per-operation factory allowlist at plugin startup.

    The module and its imports run with full gateway privileges. This is an
    integrity check for the selected source file, NOT a Python sandbox.
    """
    if not isinstance(raw, dict):
        raise ValueError('invalid consumers configuration')
    selected = Path(home).absolute()
    prepared = []
    for name, spec in raw.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError('invalid consumer name')
        if (not isinstance(spec, dict) or set(spec) not in
                ({'path', 'factory', 'sha256'},
                 {'path', 'factory', 'sha256', 'requires_verified_principal'})):
            raise ValueError('invalid consumer configuration')
        path_text, symbol, digest = spec['path'], spec['factory'], spec['sha256']
        verified = spec.get('requires_verified_principal', False)
        if (not isinstance(path_text, str) or not path_text or
                not Path(path_text).is_absolute() or '..' in Path(path_text).parts or
                not path_text.endswith('.py') or
                not isinstance(symbol, str) or not symbol.isidentifier() or symbol.startswith('_') or
                not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest) or
                type(verified) is not bool):
            raise ValueError('invalid consumer configuration')
        path = Path(path_text)
        # Refuse writable module directories as well as replaced/symlink files.
        # System ancestors such as /tmp are outside this check; use a trusted
        # deployment tree and do not import dependencies from untrusted roots.
        parent = path.parent
        info = parent.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o022):
            raise ValueError('unsafe consumer directory')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            file_info = os.fstat(fd)
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid() or
                    file_info.st_mode & 0o022 or file_info.st_size > 1024 * 1024):
                raise ValueError('unsafe consumer file')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                source = stream.read(1024 * 1024 + 1)
            if len(source) != file_info.st_size or hashlib.sha256(source).hexdigest() != digest:
                raise ValueError('consumer integrity mismatch')
        finally:
            os.close(fd)
        prepared.append((name, path, source, symbol, verified))
    # Validate every config entry before executing any configured code. If a
    # factory fails afterwards, roll back only entries created by this loader.
    added = []
    try:
        for name, path, source, symbol, verified in prepared:
            namespace = types.ModuleType('secure_env_admin_consumer_' + name)
            namespace.__file__ = str(path)
            exec(compile(source, str(path), 'exec'), namespace.__dict__)
            factory = namespace.__dict__.get(symbol)
            if not callable(factory):
                raise ValueError('missing consumer factory')
            register_consumer(selected, name, factory, requires_verified_principal=verified)
            added.append(name)
    except BaseException:
        with _LOCK:
            for name in added:
                _CONSUMERS.pop((selected, name), None)
        raise
