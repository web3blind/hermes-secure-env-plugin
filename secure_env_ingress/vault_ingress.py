"""Strict live browser/page binding for Telegram native Vault ingress."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import secrets
import time
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
    browser_backend: str = 'legacy'


@dataclass(frozen=True)
class VaultLoginTarget:
    """Storage destination, deliberately independent of any browser instance."""
    origin: str
    label: str
    session_id: str
    session_key: str


def capture_login_target(origin: str, label: str, session_id: str, session_key: str) -> VaultLoginTarget:
    strict_origin(origin)
    if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 for c in label):
        raise ValueError('invalid label')
    if not session_id or not session_key:
        raise ValueError('unbound session')
    return VaultLoginTarget(origin, label, session_id, session_key)


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
    record = None
    if target.browser_backend == 'browser-use':
        from tools.browser_use_cli import is_browser_use_cli_mode
        if not is_browser_use_cli_mode():
            raise ValueError('browser backend changed')
    elif target.browser_backend == 'legacy':
        from tools.browser_use_cli import is_browser_use_cli_mode
        if is_browser_use_cli_mode():
            raise ValueError('browser backend changed')
        key = browser._last_active_session_key.get(target.browser_task)
        if key != target.browser_key or not key:
            raise ValueError('browser changed')
        record = browser._active_sessions.get(key)
        if (record is None or id(record) != target.browser_identity
                or record.get('owner_task_id') != target.browser_task or record.get('session_key') != key):
            raise ValueError('browser changed')
    else:
        raise ValueError('unknown browser backend')
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
    if target.browser_backend == 'browser-use' and not is_browser_use_cli_mode():
        raise ValueError('browser backend changed')
    if target.browser_backend == 'legacy' and (is_browser_use_cli_mode() or browser._active_sessions.get(key) is not record or browser._last_active_session_key.get(target.browser_task) != key):
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
    from tools.browser_use_cli import is_browser_use_cli_mode
    if is_browser_use_cli_mode():
        # Compatibility contract (not exact BU_NAME/endpoint binding): the
        # existing task supervisor and its page are rechecked at issuance and
        # submission. Named browser_exec sessions may use a different tab or
        # endpoint; the host exposes no authoritative association to plugins.
        supervisor, page_session = _attached_supervisor(task_id)
        target = VaultTarget(origin, label, task_id, '', id(supervisor), session_id,
                             session_key, id(supervisor), page_session, 'browser-use')
        assert_browser_target(target)
        return target
    key = browser._last_active_session_key.get(task_id)
    record = browser._active_sessions.get(key) if key else None
    if not record or record.get('owner_task_id') != task_id or record.get('session_key') != key:
        raise ValueError('browser missing')
    supervisor, page_session = _attached_supervisor(task_id)
    target = VaultTarget(origin, label, task_id, key, id(record), session_id, session_key,
                         id(supervisor), page_session)
    assert_browser_target(target)
    return target


def fill_verification_code(target: VaultTarget, code: str, *, expires_at: float) -> bool:
    """Fill the captured page through its supervisor CDP socket, never CLI eval/argv."""
    from agent.vault_login_classifier import (LoginControl, build_fill_js,
        build_inspection_js, build_otp_fills, classify_otp_controls)
    if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9]{4,16}', code):
        raise ValueError('invalid code')
    assert_browser_target(target)
    supervisor, session = _attached_supervisor(target.browser_task)
    if id(supervisor) != target.supervisor_identity or session != target.page_session_id:
        raise ValueError('page changed')
    nonce = secrets.token_hex(8)
    inspected = supervisor.evaluate_runtime(build_inspection_js(nonce))
    if not inspected.get('ok'):
        raise ValueError('inspection failed')
    raw = inspected.get('result')
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, list):
        raise ValueError('inspection failed')
    descriptors = [LoginControl.from_dict(item) for item in raw if isinstance(item, dict)]
    # Some localized verification forms omit autocomplete and use only name=code.
    # Keep exact-name matching narrow: never select postal/promo/security-code fields
    # merely because their name contains the word 'code'. Include every candidate
    # so the ambiguity check still refuses multiple unrelated code fields.
    from agent.vault_login_classifier import ClassifiedLoginControl
    controls = classify_otp_controls(descriptors)
    classified_indices = {item.control.index for item in controls}
    for control in descriptors:
        if (control.index not in classified_indices and control.name.split()[:1] == ['code']
                and control.type in ('text', 'tel', 'number', '')
                and re.search(r'\b(?:code|код)\b', control.label, re.IGNORECASE)):
            controls.append(ClassifiedLoginControl(control, 70, 'one-time-code'))
    controls.sort(key=lambda item: item.control.index)
    if not controls:
        raise ValueError('no code field')
    fills = build_otp_fills(controls, code)
    if len(controls) != len(fills):
        raise ValueError('ambiguous code field')
    if (len(fills) == 1 and controls[0].control.max_length is not None
            and 0 <= controls[0].control.max_length < len(code)):
        raise ValueError('code field too short')
    assert_browser_target(target)
    if _attached_supervisor(target.browser_task) != (supervisor, session):
        raise ValueError('page changed')
    if time.monotonic() >= expires_at:
        raise ValueError('expired')
    # The captured supervisor's private CDP WebSocket never places code in argv.
    result = supervisor.evaluate_runtime(build_fill_js(fills, expected_origin=target.origin, nonce=nonce))
    if not result.get('ok'):
        raise ValueError('fill failed')
    output = result.get('result')
    if isinstance(output, str):
        output = json.loads(output)
    return isinstance(output, dict) and output.get('filled') == len(fills) and bool(fills)
