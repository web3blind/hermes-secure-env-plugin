"""Plugin-owned OTP discovery. No focus_page patches or model-selected CDP endpoints."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from .vault_ingress import strict_origin


@dataclass(frozen=True)
class CodeTarget:
    origin: str
    label: str
    task: str
    page: str
    nonce: str
    href: str = field(repr=False)
    controls: tuple = field(repr=False)
    supervisor: object = field(repr=False, compare=False)
    field_selector: str | None = field(default=None, kw_only=True, repr=False)
    target_spec: dict | None = field(default=None, kw_only=True, repr=False)


def _supervisor(task):
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from .bound_cdp import require_capture
    if not task or task == 'default':
        raise ValueError('browser unavailable')
    try:
        sup = SUPERVISOR_REGISTRY.capture(task)
    except Exception:
        raise ValueError('public browser capture unavailable') from None
    require_capture(sup)
    if sup.task_id != task:
        raise ValueError('browser unavailable')
    return sup


def _call(sup, method, params=None, sid=None):
    from .bound_cdp import BoundCDP
    transport = sup if isinstance(sup, BoundCDP) else BoundCDP(sup)
    return transport.call(method, params, sid)


@contextmanager
def _page(sup, page):
    result = _call(sup, 'Target.attachToTarget', {'targetId': page, 'flatten': True})
    sid = result['result']['sessionId']
    try:
        yield sid
    finally:
        try:
            _call(sup, 'Target.detachFromTarget', {'sessionId': sid})
        except Exception:
            pass


def _evaluate(sup, sid, expression):
    result = _call(sup, 'Runtime.evaluate', {'expression': expression, 'returnByValue': True}, sid)
    payload = result.get('result', {})
    if 'exceptionDetails' in payload or 'error' in result:
        raise ValueError('page unavailable')
    return payload.get('result', {}).get('value')


_FORBIDDEN_CODE = re.compile(
    r'password|парол|promo|промо|coupon|купон|discount|скид|gift|подароч|'
    r'cvv|cvc|csc|card|credit|payment|billing|postal|zip|\bpan\b|карт|платеж|'
    r'api[ _-]*key|private[ _-]*key|seed|recovery|backup|username|секрет|ключ|восстанов', re.I)
_RU_CODE = re.compile(
    r'\bкод\s+(?:подтверждения|верификации|аутентификации|из\s+(?:sms|смс|сообщения))\b|'
    r'\b(?:одноразовый|разовый)\s+код\b', re.I)


def validate_field_selector(selector, parent):
    if selector is not None and (not isinstance(selector, str) or not 1 <= len(selector) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in selector) or not isinstance(parent, str) or not parent):
        raise ValueError('invalid code field selector')


def binding_failure_detail(error):
    """Fixed diagnostic codes only; never stringify or return CDP/page errors."""
    if type(error) is not ValueError or len(error.args) != 1 or not isinstance(error.args[0], str):
        return 'binding_refused'
    return {
        'unsupported document depth': 'document_depth',
        'unsupported document capacity': 'document_capacity',
        'unsupported shadow': 'document_shadow',
        'unsupported document': 'document_unsupported',
        'ambiguous code selector': 'selector_ambiguous',
        'inadmissible code selector': 'selector_inadmissible',
        'explicit parent required': 'parent_binding',
        'task-selected parent mismatch': 'parent_binding',
        'invalid parent': 'parent_binding',
        'parent unavailable': 'parent_binding',
        'parent attachment changed': 'parent_binding',
        'parent session changed': 'parent_binding',
        'parent session closed': 'parent_binding',
        'parent connection changed': 'browser_changed',
        'browser generation unavailable': 'browser_changed',
        'browser unavailable': 'browser_unavailable',
        'public browser capture unavailable': 'browser_unavailable',
        'browser changed': 'browser_changed',
        'invalid selection': 'selection_invalid',
        'ambiguous code form': 'form_ambiguous',
        'stale nested target': 'target_changed',
        'code document changed': 'target_changed',
        'inspection changed': 'target_changed',
        'page changed': 'target_changed',
        'ancestor changed': 'target_changed',
        'frame owner changed': 'target_changed',
    }.get(error.args[0], 'binding_refused')


def _classified(raw, explicit=False):
    """Shared plugin-only OTP policy; selector evidence cannot override exclusions.

    Host inspection combines labels, placeholders and accessible-name sources.
    An unknown explicitly selected field must additionally be OTP-shaped: numeric
    input mode, name=code, bounded 4–16 maxlength, and an actual form. It is never arbitrary
    secret input. Password-type recognized passcodes retain native semantics.
    """
    from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl, classify_otp_controls
    found = []
    for row in raw:
        if not isinstance(row, dict) or row.get("groupForbidden"):
            continue
        c = LoginControl.from_dict(row)
        text = ' '.join((c.name, c.label, c.autocomplete))
        tokens = c.autocomplete.lower().split()
        # An optional leading section token groups fields; it is not a field
        # purpose. Preserve native OTP semantics without allowing other tokens.
        if tokens and re.fullmatch(r'section-[a-z0-9_-]+', tokens[0]):
            tokens = tokens[1:]
        if (c.type not in ('text', 'tel', 'number', 'password', '')
                or _FORBIDDEN_CODE.search(text)
                or any(t not in ('off', 'on', 'one-time-code') for t in tokens)):
            continue
        if explicit and (not row.get('selected') or c.type == 'password'):
            continue
        native = classify_otp_controls([c])
        if native:
            found.extend(native)
        elif (not explicit and row.get('groupedOtp') is not None
                and c.type in ('text', 'tel') and c.max_length == 1):
            found.append(ClassifiedLoginControl(c, 70, 'one-time-code'))
        elif c.type != 'password' and _RU_CODE.search(c.label):
            found.append(ClassifiedLoginControl(c, 70, 'one-time-code'))
        elif (explicit and str(row.get('fieldName', '')).lower() == 'code'
                and c.form_index is not None and row.get('inputMode') == 'numeric'
                and c.max_length is not None and 4 <= c.max_length <= 16):
            found.append(ClassifiedLoginControl(c, 70, 'one-time-code'))
    return found


def discover(origin, label, task, parent=None, field_selector=None, target_spec=None, *, saved_otp=False):
    strict_origin(origin)
    validate_field_selector(field_selector, parent)
    if target_spec is not None:
        from .exact_code import validate_spec
        target_spec = validate_spec(target_spec, parent)
        if field_selector is not None:
            raise ValueError("invalid target spec")
    if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 for c in label):
        raise ValueError('invalid label')
    if parent is not None:
        from .nested_code import discover as nested_discover
        return nested_discover(origin, label, task, parent, field_selector=field_selector, target_spec=target_spec, saved_otp=saved_otp)
    raise ValueError('explicit parent required')


def assert_target(target):
    from .nested_code import assert_target
    return assert_target(target)


def fill(target, code, expires_at):
    from .nested_code import fill
    from .exact_code import policy
    spec=target.target_spec
    if not (policy(spec).accepts(code) if spec is not None else
            isinstance(code,str) and re.fullmatch(r'[!-~]{4,16}',code)):
        raise ValueError('invalid code')
    return fill(target,code,expires_at)


def release(target):
    from .nested_code import NestedCodeTarget, release as nested_release
    if isinstance(target, NestedCodeTarget):
        nested_release(target)


class CodeSelection:
    """Short-lived selection capabilities scoped to home, owner and conversation."""
    ttl_seconds = 120

    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()
        self._closed = False
        self._timers = {}

    def _retire(self, predicate):
        # Caller holds the lock; retirement is exact, never scope-wide on cancel.
        for key, entry in list(self._entries.items()):
            if predicate(entry):
                del self._entries[key]
                release(entry[2])
        live = {entry[3] for entry in self._entries.values()}
        for batch in list(self._timers):
            if batch not in live:
                self._timers.pop(batch).cancel()

    def cancel_batch(self, batch):
        batch.set()  # Visible to a discovery worker before it acquires the lock.
        with self._lock:
            self._retire(lambda entry: entry[3] is batch)

    def _expire_batch(self, batch):
        with self._lock:
            self._retire(lambda entry: entry[3] is batch)

    def choose(self, scope, origin, label, task, selection=None, parent=None, field_selector=None, *, batch=None, target_spec=None):
        if not isinstance(parent, str) or not parent:
            raise ValueError('explicit parent required')
        validate_field_selector(field_selector, parent)
        if target_spec is not None:
            from .exact_code import validate_spec
            target_spec = validate_spec(target_spec, parent)
            if field_selector is not None:
                raise ValueError("invalid target spec")
        batch = batch if batch is not None else threading.Event()
        with self._lock:
            if self._closed or batch.is_set():
                raise ValueError('selection stopped')
            now = time.monotonic()
            self._retire(lambda entry: entry[0] <= now)
            if selection is not None:
                entry = self._entries.get(selection)
                if entry is None or entry[1] != scope or entry[2].origin != origin or entry[2].label != label:
                    raise ValueError('invalid selection')
                target = entry[2]
                if (target.task != task or (getattr(target, 'parent', None) if getattr(target, 'explicit_parent', True) else None) != parent
                        or target.field_selector != field_selector or getattr(target, 'target_spec', None) != target_spec):
                    raise ValueError('invalid selection')
                self._entries.pop(selection)
                self._retire(lambda entry: False)
                try:
                    assert_target(target)
                except BaseException:
                    release(target)
                    raise
                return target, None
        # Discovery can block in CDP. Shutdown and cancellation must not wait on it.
        from .bound_cdp import acquisition_scope
        with acquisition_scope(batch):
            targets = discover(origin, label, task) if parent is None else discover(
                origin, label, task, parent=parent, **({'field_selector': field_selector} if field_selector is not None else {}),
                **({'target_spec': target_spec} if target_spec is not None else {}))
        with self._lock:
            if self._closed or batch.is_set():
                for target in targets:
                    release(target)
                raise ValueError('selection stopped')
            if len(targets) == 1:
                return targets[0], None
            if not targets:
                return None, {'success': False, 'status': 'no_code_form',
                    'next': 'Open the requested site verification form, then retry. No secret requested.'}
            candidates = []
            self._retire(lambda entry: entry[1] == scope)
            if len(self._entries) + len(targets) > 128:
                for t in targets:
                    release(t)
                raise ValueError('selection capacity exceeded')
            deadline = time.monotonic() + self.ttl_seconds
            for t in targets:
                token = secrets.token_urlsafe(24)
                self._entries[token] = (deadline, scope, t, batch)
                path = urlsplit(t.href).path
                # Only allowlisted route words; arbitrary path segments can be secrets too.
                route = '/' + '/'.join(x if x.lower() in {'login', 'signin', 'auth', 'verify', 'challenge', 'otp', 'mfa', '2fa'}
                                      else '…' for x in path.split('/') if x)
                candidate = {'selection': token, 'origin': t.origin,
                    'page_ref': t.page,
                    'form_index': t.controls[0].control.form_index, 'code_fields': len(t.controls)}
                if parent is None:
                    candidate['route_hint'] = route[:100]
                else:
                    candidate.update(parent=parent, frame=t.frame, depth=len(t.ancestry))
                candidates.append(candidate)
            timer = threading.Timer(self.ttl_seconds, self._expire_batch, (batch,))
            timer.daemon = True
            self._timers[batch] = timer
            timer.start()
            return None, {'success': False, 'status': 'selection_required', 'candidates': candidates,
                'next': 'Choose the form for the login you initiated. Call again with its selection and the same origin/label. Do not ask the user to identify browser tabs. No secret requested yet.'}

    def close(self):
        with self._lock:
            self._closed = True
            self._retire(lambda entry: True)
