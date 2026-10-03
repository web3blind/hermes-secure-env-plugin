"""Plugin-owned OTP discovery. No focus_page patches or model-selected CDP endpoints."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
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


def _supervisor(task):
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    sup = SUPERVISOR_REGISTRY.get(task)
    if not task or task == 'default' or sup is None or sup.task_id != task or not sup._active:
        raise ValueError('browser unavailable')
    return sup


def _call(sup, method, params=None, sid=None):
    from .bound_cdp import BoundCDP
    if isinstance(sup, BoundCDP):
        return sup.call(method, params, sid)
    from tools.browser_supervisor import _schedule
    if not sup._active or sup._loop is None:
        raise ValueError('browser unavailable')
    return _schedule(sup._cdp(method, params or {}, session_id=sid, timeout=5), sup._loop, timeout=6)


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


def _classified(raw):
    from agent.vault_login_classifier import LoginControl, ClassifiedLoginControl, classify_otp_controls
    controls = [LoginControl.from_dict(x) for x in raw if isinstance(x, dict)]
    found = classify_otp_controls(controls)
    indices = {x.control.index for x in found}
    for c in controls:
        if (c.index not in indices and c.name.split()[:1] == ['code']
                and c.type in ('text', 'tel', 'number', '')
                and re.search(r'\b(?:code|код)\b', c.label, re.I)):
            found.append(ClassifiedLoginControl(c, 70, 'one-time-code'))
    return found


def discover(origin, label, task, parent=None):
    from agent.vault_login_classifier import build_inspection_js
    strict_origin(origin)
    if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 for c in label):
        raise ValueError('invalid label')
    if parent is not None:
        from .nested_code import discover as nested_discover
        return nested_discover(origin, label, task, parent)
    sup = _supervisor(task)
    pages = _call(sup, 'Target.getTargets').get('result', {}).get('targetInfos', [])
    result = []
    matching = []
    for p in pages:
        url = urlsplit(str(p.get('url', '')))
        if p.get('type') == 'page' and url.scheme + '://' + url.netloc == origin:
            matching.append(p)
    if len(matching) > 20:
        raise ValueError('too many candidate pages')
    deadline = time.monotonic() + 20
    for p in matching:
        if time.monotonic() >= deadline:
            raise ValueError('discovery timeout')
        nonce = secrets.token_hex(12)
        with _page(sup, p['targetId']) as sid:
            # href remains internal: query/path can contain login tokens.
            data = _evaluate(sup, sid, '(() => { const href=location.href; if(location.origin !== '
                + json.dumps(origin) + ') return null; const inputs = '
                + build_inspection_js(nonce) + '; const nodes = Array.from(document.querySelectorAll("input, select"));'
                + 'Object.defineProperty(document, "__hermesCodeTarget", {configurable:true, value:Object.freeze({nonce:'
                + json.dumps(nonce) + ', nodes:Object.freeze(nodes.map(e => Object.freeze({element:e, form:e.form, '
                + 'action:e.form ? e.form.action : null, method:e.form ? e.form.method : null})))})});'
                + 'return {href, inputs}; })()')
        if isinstance(data, dict) and isinstance(data.get('inputs'), str):
            data['inputs'] = json.loads(data['inputs'])
        if not isinstance(data, dict) or not isinstance(data.get('inputs'), list):
            raise ValueError('page changed')
        groups = {}
        for c in _classified(data['inputs']):
            groups.setdefault(c.control.form_index, []).append(c)
        for controls in groups.values():
            controls = sorted(controls, key=lambda c: c.control.index)
            # Multiple full-code fields within one form are ambiguous, never pick first.
            if len(controls) > 1 and not (all(c.control.max_length == 1 for c in controls)
                    and all(b.control.index == a.control.index + 1 for a, b in zip(controls, controls[1:]))):
                raise ValueError('ambiguous code form')
            result.append(CodeTarget(origin, label, task, p['targetId'], nonce,
                                     data['href'], tuple(controls), sup))
    if len(result) > 20:
        raise ValueError('too many candidate forms')
    return result


def _guard(target):
    # Stamp checks precede filling in the SAME JavaScript evaluation. Navigation,
    # replaced nodes, hidden/disabled fields, changed field attributes all refuse.
    expected = [{'index': x.control.index, 'type': x.control.type,
                 'maxLength': x.control.max_length, 'autocomplete': x.control.autocomplete}
                for x in target.controls]
    bound = json.dumps({'origin': target.origin, 'href': target.href, 'nonce': target.nonce, 'expected': expected})
    return '(() => { const b=' + bound + ''';
      if (location.origin !== b.origin || location.href !== b.href) return false;
      const state=document.__hermesCodeTarget;
      if (!state || state.nonce!==b.nonce) return false;
      return b.expected.every(c => {
        const saved=state.nodes[c.index];
        const matches=document.querySelectorAll('[data-hermes-vault-slot="' + b.nonce + ':' + c.index + '"]');
        if (!saved || matches.length!==1 || matches[0]!==saved.element) return false;
        const e=saved.element;
        if (!e.isConnected || e.form!==saved.form || e.disabled || e.readOnly || !e.getClientRects().length) return false;
        if (saved.form && (!saved.form.isConnected || saved.form.action!==saved.action || saved.form.method!==saved.method)) return false;
        const s=getComputedStyle(e);
        return s.display!=='none' && s.visibility!=='hidden' && e.type===c.type &&
          (e.getAttribute('autocomplete') || '')===c.autocomplete &&
          (e.maxLength > 0 ? e.maxLength : null)===c.maxLength;
      });
    })()'''


def assert_target(target):
    from .nested_code import NestedCodeTarget, assert_target as nested_assert
    if isinstance(target, NestedCodeTarget):
        return nested_assert(target)
    if _supervisor(target.task) is not target.supervisor:
        raise ValueError('browser changed')
    with _page(target.supervisor, target.page) as sid:
        if _evaluate(target.supervisor, sid, _guard(target)) is not True:
            raise ValueError('page changed')


def fill(target, code, expires_at):
    from agent.vault_login_classifier import build_otp_fills
    if not isinstance(code, str) or not re.fullmatch(r'[!-~]{4,16}', code):
        raise ValueError('invalid code')
    from .nested_code import NestedCodeTarget, fill as nested_fill
    if isinstance(target, NestedCodeTarget):
        return nested_fill(target, code, expires_at)
    if _supervisor(target.task) is not target.supervisor:
        raise ValueError('browser changed')
    fills = build_otp_fills(list(target.controls), code)
    if len(fills) != len(target.controls):
        raise ValueError('ambiguous code form')
    if len(fills) == 1:
        maximum = target.controls[0].control.max_length
        if maximum is not None and 0 <= maximum < len(code):
            raise ValueError('code too long')
    with _page(target.supervisor, target.page) as sid:
        if time.monotonic() >= expires_at:
            raise ValueError('expired')
        # Focus/input callbacks run synchronously and can mutate later fields.
        # Keep exact references and recheck after focus, before EVERY setter.
        js = '(() => { const valid=() => ' + _guard(target) + '; const fills=' + json.dumps(fills) + ''';
          if (!valid()) return {filled:0};
          const state=document.__hermesCodeTarget;
          const nodes=fills.map(f => state.nodes[f.index].element);
          const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          let filled=0;
          for (let i=0; i<fills.length; i++) {
            if (!valid() || document.__hermesCodeTarget!==state) return {filled};
            const e=nodes[i];
            e.focus();
            if (!valid() || document.__hermesCodeTarget!==state) return {filled};
            setter.call(e, fills[i].value);
            filled++;
            e.dispatchEvent(new Event('input', {bubbles:true}));
            e.dispatchEvent(new Event('change', {bubbles:true}));
          }
          return {filled};
        })()'''
        result = _evaluate(target.supervisor, sid, js)
    if isinstance(result, str):
        result = json.loads(result)
    return isinstance(result, dict) and result.get('filled') == len(fills) and bool(fills)


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

    def choose(self, scope, origin, label, task, selection=None, parent=None, *, batch=None):
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
                if target.task != task or getattr(target, 'parent', None) != parent:
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
            targets = discover(origin, label, task) if parent is None else discover(origin, label, task, parent=parent)
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
