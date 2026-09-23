"""On-demand HTTPS runtime. Capability state and entered values never persist here."""
from __future__ import annotations

import hashlib
import datetime as dt
import os
from pathlib import Path
import threading

from .capability_store import CapabilityStore
from .config import IngressConfig
from .leader import LeaderLock
from .server import HTTPSFormServer, HTTPError
from .telegram_webapp import verify_init_data, InitDataError
from .tls import validate_certificate, create_server_ssl_context
from .writer import add_missing


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
        with self._lock:
            if self._closed or owner not in self.config.allowed_telegram_user_ids:
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
                    platform='telegram', user_id=owner, hermes_home=self.home,
                    profile_name=name, allowed_keys=resolved.profile.keys,
                    target_id=self._target_id(resolved.target),
                    ttl_seconds=self.config.ttl_seconds,
                )
                self._targets = {browser.group_id: resolved}
                if self._monitor is None or not self._monitor.is_alive():
                    self._stop.clear()
                    self._monitor = threading.Thread(target=self._watch, daemon=True, name='secure-env-expiry')
                    self._monitor.start()
                origin = self._origin()
                return {
                    'url': f'{origin}/e#{browser.token}',
                    'web_app_url': f'{origin}/e#{mini.token}' if self.config.mini_app_enabled else None,
                }
            except Exception:
                self._stop_listener()
                raise

    def _claim(self, token, init_data):
        claim = self._store.peek(token)
        if claim is None or claim.group_id not in self._targets:
            raise HTTPError(410, 'invalid_session')
        if claim.mode == 'mini':
            if not self.config.mini_app_enabled:
                raise HTTPError(403, 'invalid_session')
            try:
                verify_init_data(init_data, self._bot_token, expected_user_id=claim.user_id,
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
            return {'label': claim.profile_name, 'keys': list(claim.allowed_keys)}

    def submit(self, token, init_data, values):
        with self._lock:
            if self._closed:
                raise HTTPError(403, 'invalid_session')
            claim = self._claim(token, init_data)
            resolved = self._targets[claim.group_id]
            consumed = self._store.consume(token, mode=claim.mode, platform='telegram',
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

    def reject_submission(self, token, init_data):
        """Authenticated malformed submission is terminal, without writing."""
        with self._lock:
            claim = self._claim(token, init_data)
            self._store.cancel(platform='telegram', user_id=claim.user_id, hermes_home=self.home)
            self._targets.clear()

    def cancel(self, owner):
        with self._lock:
            if self._store.cancel(platform='telegram', user_id=owner, hermes_home=self.home):
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
