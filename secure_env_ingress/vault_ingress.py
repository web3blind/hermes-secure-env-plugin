"""Strict live browser/page binding for Telegram native Vault ingress."""
from __future__ import annotations

from dataclasses import dataclass
import stat
import os
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class VaultTarget:
    origin: str
    label: str
    browser_task: str
    browser_key: str
    browser_identity: int
    session_id: str
    session_key: str
    supervisor_identity: int | None = None
    page_session_id: str | None = None


def strict_origin(value: str) -> str:
    if not isinstance(value, str) or len(value) > 170 or not value.isascii() or any(c.isspace() or ord(c) < 33 for c in value):
        raise ValueError('invalid origin')
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError('invalid origin') from None
    if (parsed.scheme != 'https' or not host or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or value.endswith('/')
            or (port is not None and port == 443)):
        raise ValueError('invalid origin')
    from agent.vault_store import normalize_origin
    if normalize_origin(value) != value:
        raise ValueError('invalid origin')
    return value


@dataclass(frozen=True)
class VaultHomeBinding:
    home: Path
    components: tuple[tuple[str, int, int] | tuple[str, None, None], ...]


def _home_components(home: Path) -> VaultHomeBinding:
    """Record directory identity and reject symlinks at every path component."""
    if '..' in Path(home).parts:
        raise ValueError('unsafe profile path')
    path = Path(home).absolute()
    components = []
    for candidate in (*reversed(path.parents), path, path / 'vault'):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if candidate != path / 'vault':
                raise ValueError('profile directory missing') from None
            components.append((str(candidate), None, None))
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('symlink or non-directory in vault path')
        if candidate in (path, path / 'vault') and (
                info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError('unsafe vault directory permissions')
        components.append((str(candidate), info.st_dev, info.st_ino))
    vault = path / 'vault'
    for name in ('.vault.lock', 'vault.key', 'vault.json.enc'):
        file = vault / name
        try:
            info = file.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or (name != '.vault.lock' and info.st_mode & 0o077)):
            raise ValueError('unsafe vault file')
    return VaultHomeBinding(path, tuple(components))


def bind_vault_home(home: Path) -> VaultHomeBinding:
    assert_profile_home(home)
    return _home_components(home)


def assert_vault_home(binding: VaultHomeBinding) -> None:
    assert_profile_home(binding.home)
    if _home_components(binding.home) != binding:
        raise ValueError('vault path changed')


def assert_profile_home(home: Path) -> None:
    from hermes_constants import get_hermes_home
    if Path(get_hermes_home()).absolute() != Path(home).absolute():
        raise ValueError('profile changed')
    _home_components(home)


def _attached_supervisor(task_id: str):
    """Only an existing native CDP attachment qualifies; never launch or refocus."""
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    supervisor = SUPERVISOR_REGISTRY.get(task_id)
    if supervisor is None or supervisor.task_id != task_id:
        raise ValueError('browser supervisor missing')
    with supervisor._state_lock:
        if not supervisor._active or not supervisor._page_session_id:
            raise ValueError('page unavailable')
        session = supervisor._page_session_id
    return supervisor, session


def assert_browser_target(target: VaultTarget) -> None:
    """Check the captured supervisor/page session before and after live origin evaluation."""
    from tools import browser_tool as browser
    if not target.browser_task or target.browser_task == 'default':
        raise ValueError('browser task missing')
    key = browser._last_active_session_key.get(target.browser_task)
    if key != target.browser_key or not key:
        raise ValueError('browser changed')
    record = browser._active_sessions.get(key)
    if (record is None or id(record) != target.browser_identity
            or record.get('owner_task_id') != target.browser_task or record.get('session_key') != key):
        raise ValueError('browser changed')
    supervisor, session = _attached_supervisor(target.browser_task)
    if target.supervisor_identity != id(supervisor) or target.page_session_id != session:
        raise ValueError('page changed')
    result = supervisor.evaluate_runtime('location.href')
    href = result.get('result') if result.get('ok') else None
    if not isinstance(href, str):
        raise ValueError('page unavailable')
    from agent.vault_store import normalize_origin
    try:
        if not href.startswith('https://') or normalize_origin(href) != target.origin:
            raise ValueError('page changed')
    except (TypeError, ValueError) as exc:
        raise ValueError('page changed') from exc
    if browser._active_sessions.get(key) is not record or browser._last_active_session_key.get(target.browser_task) != key:
        raise ValueError('browser changed')
    current_supervisor, current_session = _attached_supervisor(target.browser_task)
    if current_supervisor is not supervisor or current_session != session:
        raise ValueError('page changed')


def capture_browser_target(origin: str, label: str, task_id: str, session_id: str, session_key: str) -> VaultTarget:
    strict_origin(origin)
    if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 for c in label):
        raise ValueError('invalid label')
    from tools import browser_tool as browser
    if not task_id or task_id == 'default' or task_id != session_id:
        raise ValueError('unbound task')
    key = browser._last_active_session_key.get(task_id)
    record = browser._active_sessions.get(key) if key else None
    if not record or record.get('owner_task_id') != task_id or record.get('session_key') != key:
        raise ValueError('browser missing')
    supervisor, page_session = _attached_supervisor(task_id)
    target = VaultTarget(origin, label, task_id, key, id(record), session_id, session_key,
                         id(supervisor), page_session)
    assert_browser_target(target)
    return target
