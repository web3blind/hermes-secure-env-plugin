"""On-demand HTTPS runtime. Capability state and entered values never persist here."""
from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, field
import datetime as dt
import os
from pathlib import Path
import threading
import contextvars
import time
from concurrent.futures import Future

from .capability_store import CapabilityStore
from .config import IngressConfig
from .leader import LeaderLock
from .server import HTTPSFormServer, HTTPError
from .telegram_webapp import verify_init_data, InitDataError
from .tls import validate_certificate, create_server_ssl_context
from .writer import add_missing
from .vault_ingress import VaultTarget, assert_browser_target, assert_profile_home, bind_vault_home, assert_vault_home

# Browser Vault form fields. The authenticator setup key is optional (empty when the site has no
# authenticator app); when present it is stored with the login so the native vault can mint 2FA codes
# itself — the code then never travels through the chat.
VAULT_LOGIN_KEYS = ('Username', 'Password', 'Authenticator key (optional)')
CODE_KEYS = ('Verification code',)
OPERATION_KEYS = ('Secret',)

@dataclass(frozen=True)
class OperationTarget:
    name: str
    summary: str
    execute: object = field(repr=False)
    identity: tuple[int, int]
    session_key: str
    chat: str
    thread: str


class IngressRuntime:
    def __init__(self, settings, home, bot_token, *, trust_roots=None):
        if os.geteuid() == 0:
            raise RuntimeError("secure ingress requires a non-root runtime account")
        self.config = IngressConfig.from_mapping(settings)
        self.home = Path(home)
        self._bot_token = bot_token
        self._trust_roots = trust_roots  # explicit offline-test injection, not a plugin setting
        self._lock = threading.RLock()
        self._leader = LeaderLock(self.home)
        self._store = CapabilityStore()
        self._targets = {}
        self._completion = None
        self._vault_context = None
        self._vault_binding = None
        self._code_groups = set()
        self._operation_groups = set()
        self._operation_context = None
        self._operation_inflight = None  # (group, owner); persists until callback returns
        self._server = None
        self._closed = False
        self._stop = threading.Event()
        self._monitor = None

    def _tls(self):
        return validate_certificate(
            self.config.cert_path, self.config.key_path,
            expected_ip=self.config.public_ip, trust_roots=self._trust_roots,
            minimum_remaining=dt.timedelta(seconds=self.config.safety_seconds),
        )

    @staticmethod
    def _target_id(target):
        identity = (str(target.path), target.parent_identity, target.file_identity)
        digest = hashlib.sha256(repr(identity).encode("utf-8")).digest()
        return (int.from_bytes(digest, "big"), target.expected_uid)

    def _origin(self):
        ip = self.config.public_ip
        host = f'[{ip}]' if ':' in ip else ip
        return f'https://{host}:{self.config.listen_port}'

    def create(self, owner, name):
        owner = ('telegram', str(owner)) if type(owner) is int else owner
        with self._lock:
            if self._closed or owner not in self.config.owners:
                raise HTTPError(403, 'denied')
            self._tls()
            resolved = self.config.resolve(name, hermes_home=self.home, expected_uid=os.getuid())
            self._leader.acquire()
            try:
                if self._server is None:
                    context = create_server_ssl_context(
                        self.config.cert_path, self.config.key_path,
                        expected_ip=self.config.public_ip, trust_roots=self._trust_roots,
                    )
                    self._server = HTTPSFormServer(
                        (self.config.listen_host, self.config.listen_port), context, self,
                    )
                    self._server.start()
                browser, mini = self._store.issue_pair(
                    platform=owner[0], user_id=owner[1], hermes_home=self.home,
                    profile_name=name, allowed_keys=resolved.profile.keys,
                    target_id=self._target_id(resolved.target),
                    ttl_seconds=self.config.ttl_seconds,
                )
                self._targets = {browser.group_id: resolved}
                self._finish_completion('superseded')
                if self._monitor is None or not self._monitor.is_alive():
                    self._stop.clear()
                    self._monitor = threading.Thread(target=self._watch, daemon=True, name='secure-env-expiry')
                    self._monitor.start()
                origin = self._origin()
                return {
                    'url': f'{origin}/e#{browser.token}',
                    'web_app_url': f'{origin}/e#{mini.token}' if self.config.mini_app_enabled and self._bot_token and owner[0] == 'telegram' else None,
                    'group_id': browser.group_id,
                }
            except Exception:
                self._stop_listener()
                raise

    def create_vault(self, owner, target: VaultTarget, *, mode='login'):
        with self._lock:
            if (self._closed or not isinstance(owner, tuple) or len(owner) != 2
                    or owner[0] != 'telegram' or owner not in self.config.owners
                    or mode not in ('login', 'code')):
                raise HTTPError(403, 'denied')
            assert_profile_home(self.home)
            assert_browser_target(target)
            binding = bind_vault_home(self.home) if mode == 'login' else None
            self._tls()
            self._leader.acquire()
            try:
                if self._server is None:
                    context = create_server_ssl_context(self.config.cert_path, self.config.key_path,
                                                        expected_ip=self.config.public_ip, trust_roots=self._trust_roots)
                    self._server = HTTPSFormServer((self.config.listen_host, self.config.listen_port), context, self)
                    self._server.start()
                browser, mini = self._store.issue_pair(
                    platform=owner[0], user_id=owner[1], hermes_home=self.home,
                    profile_name='browser_vault_code' if mode == 'code' else 'browser_vault',
                    allowed_keys=CODE_KEYS if mode == 'code' else VAULT_LOGIN_KEYS,
                    target_id=(target.browser_identity, os.getuid()),
                    ttl_seconds=min(self.config.ttl_seconds, 240))
                self._targets = {browser.group_id: target}
                self._finish_completion('superseded')
                self._code_groups.clear()
                if mode == 'code':
                    self._code_groups.add(browser.group_id)
                from hermes_constants import set_hermes_home_override, reset_hermes_home_override
                scope = set_hermes_home_override(self.home)
                try:
                    self._vault_context = (browser.group_id, contextvars.copy_context())
                finally:
                    reset_hermes_home_override(scope)
                completion = Future()
                self._completion = (browser.group_id, completion)
                self._vault_binding = (browser.group_id, binding) if binding is not None else None
                if self._monitor is None or not self._monitor.is_alive():
                    self._stop.clear()
                    self._monitor = threading.Thread(target=self._watch, daemon=True, name='secure-env-expiry')
                    self._monitor.start()
                base = self._origin()
                return {'url': f'{base}/e#{browser.token}',
                        'web_app_url': f'{base}/e#{mini.token}' if self.config.mini_app_enabled and self._bot_token else None,
                        'group_id': browser.group_id, 'completion': completion,
                        'expires_at': browser.expires_at}
            except Exception:
                self._stop_listener()
                raise

    def create_operation(self, owner, target: OperationTarget):
        with self._lock:
            if (self._closed or owner not in self.config.owners or not isinstance(target, OperationTarget)):
                raise HTTPError(403, 'denied')
            if self._operation_inflight is not None:
                raise HTTPError(409, 'operation_busy')
            from hermes_constants import profile_name_for_home
            profile = profile_name_for_home(self.home) or 'default'
            self._tls()
            self._leader.acquire()
            try:
                if self._server is None:
                    context = create_server_ssl_context(self.config.cert_path, self.config.key_path,
                                                        expected_ip=self.config.public_ip, trust_roots=self._trust_roots)
                    self._server = HTTPSFormServer((self.config.listen_host, self.config.listen_port), context, self)
                    self._server.start()
                browser, _mini = self._store.issue_pair(
                    platform=owner[0], user_id=owner[1], hermes_home=self.home,
                    profile_name=profile, allowed_keys=OPERATION_KEYS,
                    target_id=target.identity, ttl_seconds=min(self.config.ttl_seconds, 240))
                self._targets = {browser.group_id: target}
                self._finish_completion('superseded')
                self._operation_groups.clear()
                self._operation_groups.add(browser.group_id)
                from hermes_constants import set_hermes_home_override, reset_hermes_home_override
                scope = set_hermes_home_override(self.home)
                try:
                    self._operation_context = (browser.group_id, contextvars.copy_context())
                finally:
                    reset_hermes_home_override(scope)
                completion = Future()
                self._completion = (browser.group_id, completion)
                if self._monitor is None or not self._monitor.is_alive():
                    self._stop.clear()
                    self._monitor = threading.Thread(target=self._watch, daemon=True, name='secure-env-expiry')
                    self._monitor.start()
                return {'url': f'{self._origin()}/e#{browser.token}', 'group_id': browser.group_id,
                        'completion': completion, 'expires_at': browser.expires_at}
            except Exception:
                self._stop_listener()
                raise

    def _claim(self, token, init_data):
        claim = self._store.peek(token)
        if claim is None or claim.group_id not in self._targets:
            raise HTTPError(410, 'invalid_session')
        if claim.group_id in self._operation_groups and claim.mode != 'browser':
            raise HTTPError(403, 'invalid_session')
        if claim.mode == 'mini':
            if not self.config.mini_app_enabled or claim.platform != 'telegram' or not self._bot_token:
                raise HTTPError(403, 'invalid_session')
            try:
                verify_init_data(init_data, self._bot_token, expected_user_id=int(claim.user_id),
                                 max_age_seconds=self.config.ttl_seconds)
            except InitDataError:
                raise HTTPError(403, 'invalid_session') from None
        elif init_data:
            raise HTTPError(403, 'invalid_session')
        return claim

    def session(self, token, init_data):
        with self._lock:
            if self._closed:
                raise HTTPError(403, 'invalid_session')
            claim = self._claim(token, init_data)
            target = self._targets[claim.group_id]
            if isinstance(target, OperationTarget):
                return {'label': target.name, 'keys': list(OPERATION_KEYS),
                        'kind': 'secure_operation', 'summary': target.summary}
            if isinstance(target, VaultTarget):
                from hermes_constants import profile_name_for_home
                profile = profile_name_for_home(self.home) or 'default'
                code_mode = claim.group_id in self._code_groups
                return {'label': target.label + ' — ' + target.origin + ' — Profile: ' + profile,
                        'keys': list(CODE_KEYS if code_mode else VAULT_LOGIN_KEYS),
                        'kind': 'browser_code' if code_mode else 'browser_vault'}
            return {'label': claim.profile_name, 'keys': list(claim.allowed_keys)}

    def submit(self, token, init_data, values):
        with self._lock:
            if self._closed:
                raise HTTPError(403, 'invalid_session')
            claim = self._claim(token, init_data)
            resolved = self._targets[claim.group_id]
            if isinstance(resolved, OperationTarget):
                context = self._submit_operation(token, claim, resolved, values)
            else:
                context = None
            if isinstance(resolved, VaultTarget):
                bound_context = self._vault_context
                if (bound_context is None or bound_context[0] != claim.group_id or
                        (claim.group_id not in self._code_groups and
                         (self._vault_binding is None or self._vault_binding[0] != claim.group_id))):
                    raise HTTPError(410, 'invalid_session')
                if claim.group_id in self._code_groups:
                    return bound_context[1].copy().run(self._submit_code, token, claim, resolved, values)
                return bound_context[1].copy().run(self._submit_vault, token, claim, resolved, values)
            if not isinstance(resolved, OperationTarget):
                consumed = self._store.consume(token, mode=claim.mode, platform=claim.platform,
                                           user_id=claim.user_id, hermes_home=self.home,
                                           profile_name=resolved.profile.name,
                                           allowed_keys=resolved.profile.keys,
                                           target_id=self._target_id(resolved.target))
                if consumed is None:
                    raise HTTPError(410, 'invalid_session')
                self._targets.clear()
                if (not isinstance(values, list) or len(values) != len(claim.allowed_keys)
                    or any(not isinstance(v, str) or not v or len(v.encode('utf-8')) > 16384
                           or any(c in v for c in ('\r', '\n', '\x00')) or '${' in v for v in values)):
                    raise HTTPError(400, 'invalid_values')
                try:
                    result = add_missing(resolved.target.path, dict(zip(claim.allowed_keys, values)),
                                     binding=resolved.target, require_all_missing=True)
                    return {'added': list(result.added)}
                except HTTPError:
                    raise
                except Exception:
                    raise HTTPError(409, 'write_failed') from None
        # A trusted callback can block indefinitely; never hold the lifecycle lock here.
        return self._execute_operation(claim.group_id, resolved, values[0], context)

    def _submit_operation(self, token, claim, target, values):
        from hermes_constants import profile_name_for_home
        if claim.profile_name != (profile_name_for_home(self.home) or 'default'):
            raise HTTPError(403, 'invalid_session')
        consumed = self._store.consume(token, mode='browser', platform=claim.platform,
            user_id=claim.user_id, hermes_home=self.home, profile_name=claim.profile_name,
            allowed_keys=OPERATION_KEYS, target_id=target.identity)
        if consumed is None:
            raise HTTPError(410, 'invalid_session')
        self._targets.pop(claim.group_id, None)
        self._operation_groups.discard(claim.group_id)
        if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str)
                or not values[0] or len(values[0].encode('utf-8')) > 4096):
            self._finish_completion('rejected', claim.group_id)
            raise HTTPError(400, 'invalid_values')
        if time.monotonic() >= claim.expires_at:
            self._finish_completion('expired', claim.group_id)
            raise HTTPError(410, 'invalid_session')
        bound = self._operation_context
        if bound is None or bound[0] != claim.group_id:
            self._finish_completion('unknown', claim.group_id)
            raise HTTPError(409, 'operation_unconfirmed')
        self._operation_inflight = (claim.group_id, (claim.platform, claim.user_id))
        return bound[1].copy()

    def _execute_operation(self, group_id, target, secret, context):
        try:
            # Trusted in-process callable. Its result is intentionally discarded.
            result = context.run(target.execute, secret)
            if inspect.isawaitable(result):
                # Never report an unawaited/asynchronous action as complete.
                close = getattr(result, 'close', None)
                if callable(close):
                    close()
                raise RuntimeError('asynchronous consumer result')
        except BaseException:
            # It may have acted before raising. No retry or exception text.
            with self._lock:
                self._finish_completion('unknown', group_id)
            raise HTTPError(409, 'operation_unconfirmed') from None
        else:
            with self._lock:
                pending = self._completion is not None and self._completion[0] == group_id
                self._finish_completion('completed', group_id)
            if pending:
                return {'completed': True}
            raise HTTPError(409, 'operation_unconfirmed')
        finally:
            with self._lock:
                if self._operation_inflight is not None and self._operation_inflight[0] == group_id:
                    self._operation_inflight = None

    def _submit_code(self, token, claim, target, values):
        consumed = self._store.consume(token, mode=claim.mode, platform=claim.platform,
            user_id=claim.user_id, hermes_home=self.home, profile_name='browser_vault_code',
            allowed_keys=CODE_KEYS, target_id=(target.browser_identity, os.getuid()))
        if consumed is None:
            raise HTTPError(410, 'invalid_session')
        self._targets.pop(claim.group_id, None)
        self._code_groups.discard(claim.group_id)
        if (not isinstance(values, list) or len(values) != 1 or
                not isinstance(values[0], str) or len(values[0]) > 16 or
                not values[0].isascii() or not values[0].isalnum() or len(values[0]) < 4):
            self._finish_completion('rejected', claim.group_id)
            raise HTTPError(400, 'invalid_values')
        try:
            assert_profile_home(self.home)
            if time.monotonic() >= claim.expires_at:
                self._finish_completion('expired', claim.group_id)
                raise HTTPError(410, 'invalid_session')
            from .vault_ingress import fill_verification_code
            filled = fill_verification_code(target, values[0], expires_at=claim.expires_at)
        except HTTPError:
            raise
        except Exception:
            # A CDP timeout can occur after the page has already received the code.
            self._finish_completion('unknown', claim.group_id)
            raise HTTPError(409, 'fill_unconfirmed') from None
        if not filled:
            self._finish_completion('unknown', claim.group_id)
            raise HTTPError(409, 'fill_unconfirmed')
        self._finish_completion('filled', claim.group_id, origin=target.origin)
        return {'filled': True}

    def _submit_vault(self, token, claim, target, values):
        consumed = self._store.consume(token, mode=claim.mode, platform=claim.platform,
                                       user_id=claim.user_id, hermes_home=self.home,
                                       profile_name='browser_vault', allowed_keys=VAULT_LOGIN_KEYS,
                                       target_id=(target.browser_identity, os.getuid()))
        if consumed is None:
            raise HTTPError(410, 'invalid_session')
        self._targets.pop(claim.group_id, None)
        self._vault_context = None
        binding = self._vault_binding[1]
        self._vault_binding = None
        if (not isinstance(values, list) or len(values) not in (2, 3)
                or any(not isinstance(v, str) or len(v.encode('utf-8')) > 16384
                       or any(c in v for c in ('\r', '\n', '\x00')) for v in values)
                or not values[0] or not values[1]):
            self._finish_completion('rejected', claim.group_id)
            raise HTTPError(400, 'invalid_values')
        secret = {'identifier_type': 'username', 'identifier': values[0], 'password': values[1]}
        if len(values) == 3 and values[2].strip():
            # Optional third field: the authenticator setup key. Validate it here so a typo is reported
            # as such (and never as an unknown write outcome), and store the canonical form.
            from agent.vault_store import normalize_otp_secret, totp_now
            try:
                otp_secret = normalize_otp_secret(values[2])
                # Native normalization checks alphabet/parameters but not base32
                # decoding. Exercise the native code generator before any write.
                if not otp_secret or not totp_now(otp_secret, at=0):
                    raise ValueError('unusable key')
            except Exception:
                # Never reflect exception text: it may contain the submitted key.
                self._finish_completion('rejected', claim.group_id)
                raise HTTPError(400, 'invalid_authenticator_key') from None
            # The native writer normalizes again; for non-default URI parameters
            # it accepts the original URI, not the canonical pipe-delimited form.
            secret['otp_secret'] = values[2] if '|' in otp_secret else otp_secret
        try:
            assert_profile_home(self.home)
            assert_browser_target(target)
            assert_vault_home(binding)
            from agent.vault_store import VaultStore
            store = VaultStore(self.home / 'vault')
        except Exception:
            self._finish_completion('failed', claim.group_id)
            raise HTTPError(409, 'write_failed') from None
        if time.monotonic() >= claim.expires_at:
            self._finish_completion('expired', claim.group_id)
            raise HTTPError(410, 'invalid_session')
        try:
            meta = store.add_item('login', target.label, secret, origin=target.origin)
            after = bind_vault_home(self.home)
            if after.components[:-1] != binding.components[:-1] or (
                    binding.components[-1][1] is not None and after.components[-1] != binding.components[-1]):
                raise RuntimeError('vault directory changed')
            if (meta.origin != target.origin or meta.kind != 'login' or
                    not any(item.id == meta.id and item.origin == target.origin and
                            item.kind == 'login' for item in store.list_items())):
                raise RuntimeError('native Vault contract changed')
            self._finish_completion('saved', claim.group_id, handle=meta.id, origin=target.origin)
            return {'saved': True}
        except Exception:
            self._finish_completion('unknown', claim.group_id)
            raise HTTPError(409, 'write_failed') from None

    def _finish_completion(self, status, group_id=None, **metadata):
        current = self._completion
        if current is not None and (group_id is None or current[0] == group_id):
            if (self._operation_inflight is not None and self._operation_inflight[0] == current[0]
                    and status != 'completed'):
                status = 'unknown'  # Revocation does not stop an already running callback.
            self._completion = None
            if not current[1].done():
                current[1].set_result({'status': status, **metadata})
            if self._vault_binding is not None and self._vault_binding[0] == current[0]:
                self._vault_binding = None
            if self._vault_context is not None and self._vault_context[0] == current[0]:
                self._vault_context = None
            self._code_groups.discard(current[0])
            self._operation_groups.discard(current[0])
            if self._operation_context is not None and self._operation_context[0] == current[0]:
                self._operation_context = None

    def reject_submission(self, token, init_data):
        """Authenticated malformed submission is terminal, without writing."""
        with self._lock:
            claim = self._claim(token, init_data)
            self._store.cancel_group(claim.group_id)
            self._targets.pop(claim.group_id, None)
            self._finish_completion('rejected', claim.group_id)

    def cancel_group(self, group_id):
        with self._lock:
            self._finish_completion('cancelled', group_id)
            if self._store.cancel_group(group_id):
                self._targets.pop(group_id, None)
                if not self._store.active_count:
                    self._stop_listener()

    def cancel(self, owner):
        owner = ('telegram', str(owner)) if type(owner) is int else owner
        with self._lock:
            if self._operation_inflight is not None and self._operation_inflight[1] == owner:
                self._finish_completion('unknown', self._operation_inflight[0])
            if self._store.cancel(platform=owner[0], user_id=owner[1], hermes_home=self.home):
                self._finish_completion('cancelled')
                self._targets.clear()
                self._stop_listener()

    def status(self):
        with self._lock:
            try:
                self._tls()
                tls = 'Certificate verified'
            except Exception:
                tls = 'TLS is not ready'
            active = 'an active session exists' if self._store.active_count else 'no active sessions'
            return f'{tls}; {active}. Mini App: ' + ('enabled by the operator.' if self.config.mini_app_enabled else 'disabled; client compatibility has not been verified.')

    def preflight(self):
        # Read-only: validation never creates capabilities, lock files or listeners.
        return self.status() + ' External reachability and screen reader support require separate verification.'

    def _stop_listener(self):
        self._finish_completion('cancelled' if self._closed else 'expired')
        server, self._server = self._server, None
        if server is not None:
            server.stop()
        self._store.clear()
        self._targets.clear()
        self._leader.close()

    def _watch(self):
        while not self._stop.wait(0.25):
            with self._lock:
                if not self._store.active_count:
                    self._stop_listener()
                    self._monitor = None
                    return

    def close(self):
        with self._lock:
            self._closed = True
            self._stop.set()
            self._stop_listener()
            self._bot_token = ''
        if self._monitor is not None and self._monitor is not threading.current_thread():
            self._monitor.join(timeout=2)
