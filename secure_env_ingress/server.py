"""Small HTTPS-only form server for secret ingress.

Integration interface (implemented by the parent plugin)::

    backend.session(token: str, init_data: str) -> dict
    backend.submit(token: str, init_data: str, values: list[str]) -> dict

The backend owns capability lookup, Telegram policy/verification, atomic capability
consumption, and the atomic secret write. It may raise :class:`HTTPError` with a
safe machine-readable code. ``start()`` starts one daemon serve thread and
returns it; ``stop()`` shuts down, closes the listener, and joins that thread.
An already configured server-side ``ssl.SSLContext`` is mandatory.
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from typing import Any, Protocol
from urllib.parse import urlsplit

_ROOT = Path(__file__).resolve().parent
_TEMPLATE = _ROOT / "templates" / "entry.html"
_STATIC = _ROOT / "static"
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class Backend(Protocol):
    def session(self, token: str, init_data: str) -> dict[str, Any]: ...
    def submit(self, token: str, init_data: str, values: list[str]) -> dict[str, Any]: ...


class HTTPError(Exception):
    """A status and public code safe to return without exception detail."""

    def __init__(self, status: int, code: str) -> None:
        if status < 400 or status > 599:
            raise ValueError("HTTPError status must be 4xx or 5xx")
        if not _SAFE_CODE.fullmatch(code):
            raise ValueError("unsafe HTTP error code")
        super().__init__(code)
        self.status = status
        self.code = code


class _RateLimiter:
    def __init__(self, window: float, max_entries: int) -> None:
        self.window = window
        self.max_entries = max_entries
        self._entries: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self._lock:
            item = self._entries.pop(key, None)
            if item is None or now - item[0] >= self.window:
                item = (now, 0)
            started, count = item
            count += 1
            self._entries[key] = (started, count)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
            return count <= limit

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, *args: Any, max_threads: int = 16, **kwargs: Any) -> None:
        self._thread_slots = threading.BoundedSemaphore(max_threads)
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._thread_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._thread_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._thread_slots.release()


class HTTPSFormServer(_BoundedThreadingHTTPServer):
    """HTTPS form endpoint with bounded input, threads, and rate state."""

    max_body_bytes = 64 * 1024
    max_init_data_bytes = 8192
    max_token_bytes = 1024
    max_values = 64
    max_value_bytes = 16 * 1024
    request_timeout_seconds = 10.0

    def __init__(
        self,
        address: tuple[str, int],
        ssl_context: ssl.SSLContext,
        backend: Backend,
        *,
        per_ip_limit: int = 60,
        per_capability_limit: int = 20,
        rate_window_seconds: float = 60.0,
        max_rate_entries: int = 2048,
        max_threads: int = 16,
    ) -> None:
        if not isinstance(ssl_context, ssl.SSLContext):
            raise TypeError("a server SSLContext is required")
        if min(per_ip_limit, per_capability_limit, max_rate_entries, max_threads) < 1:
            raise ValueError("limits must be positive")
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self._ssl_context = ssl_context
        self.backend = backend
        self.per_ip_limit = per_ip_limit
        self.per_capability_limit = per_capability_limit
        self._rates = _RateLimiter(rate_window_seconds, max_rate_entries)
        self._serve_thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._stopped = False
        super().__init__(address, _Handler, bind_and_activate=False, max_threads=max_threads)
        try:
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def get_request(self) -> tuple[ssl.SSLSocket, Any]:
        """Accept promptly; defer the bounded TLS handshake to a worker thread."""
        request, client_address = self.socket.accept()
        request.settimeout(self.request_timeout_seconds)
        try:
            tls_request = self._ssl_context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
        except BaseException:
            request.close()
            raise
        return tls_request, client_address

    def finish_request(self, request: Any, client_address: Any) -> None:
        """Complete TLS inside the bounded request worker before parsing HTTP."""
        if not isinstance(request, ssl.SSLSocket):
            raise TypeError("TLS request required")
        request.settimeout(self.request_timeout_seconds)
        request.do_handshake()
        super().finish_request(request, client_address)

    def start(self) -> threading.Thread:
        """Start serving in one daemon thread and return that thread."""
        with self._lifecycle_lock:
            if self._stopped:
                raise RuntimeError("server has been stopped")
            if self._serve_thread is not None:
                return self._serve_thread
            thread = threading.Thread(
                target=self.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="secure-env-https",
                daemon=True,
            )
            self._serve_thread = thread
            thread.start()
            return thread

    def stop(self) -> None:
        """Idempotently stop serving, close the socket, and join the serve thread."""
        with self._lifecycle_lock:
            if self._stopped:
                return
            self._stopped = True
            thread = self._serve_thread
        if thread is not None and thread.is_alive():
            self.shutdown()
        self.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    @property
    def rate_entry_count(self) -> int:
        return self._rates.size

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Suppress stdlib traceback/client-address output at the HTTP boundary."""
        return


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


class _Handler(BaseHTTPRequestHandler):
    server: HTTPSFormServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.request_timeout_seconds)

    def log_message(self, format: str, *args: Any) -> None:
        # Request paths can contain launch parameters. Do not log them.
        return

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in {"/e", "/e/"}:
            self._send_file(_TEMPLATE, "text/html; charset=utf-8")
        elif path == "/static/entry.css":
            self._send_file(_STATIC / "entry.css", "text/css; charset=utf-8")
        elif path == "/static/entry.js":
            self._send_file(_STATIC / "entry.js", "text/javascript; charset=utf-8")
        else:
            self._error(HTTPStatus.NOT_FOUND, "not_found")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in {"/session", "/submit"}:
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        ip = self.client_address[0]
        if not self.server._rates.allow("ip:" + ip, self.server.per_ip_limit):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")
            return
        token = None
        init_data = None
        try:
            payload = self._read_json()
            token = self._bounded_string(payload.get("token"), self.server.max_token_bytes)
            init_data = self._bounded_string(payload.get("initData"), self.server.max_init_data_bytes)
            required = {"token", "initData"} | ({"values"} if path == "/submit" else set())
            if set(payload) != required:
                raise HTTPError(400, "invalid_request")
            cap_key = "cap:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
            if not self.server._rates.allow(cap_key, self.server.per_capability_limit):
                raise HTTPError(429, "rate_limited")
            if path == "/session":
                result = self.server.backend.session(token, init_data)
                result = self._validate_session_result(result)
            else:
                values = self._validate_values(payload["values"])
                result = self.server.backend.submit(token, init_data, values)
                result = self._validate_submit_result(result)
            self._json(HTTPStatus.OK, result)
        except HTTPError as exc:
            self._reject_submission(path, token, init_data)
            self._error(exc.status, exc.code)
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError, TypeError):
            self._reject_submission(path, token, init_data)
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request")
        except (BrokenPipeError, ConnectionError, socket.timeout):
            self.close_connection = True
        except Exception:
            # No exception text or request body crosses the trust boundary.
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

    def _reject_submission(self, path, token, init_data):
        if path == "/submit" and token is not None and init_data is not None:
            reject = getattr(self.server.backend, "reject_submission", None)
            if reject is not None:
                try:
                    reject(token, init_data)
                except Exception:
                    pass  # already consumed, expired or unauthenticated

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise HTTPError(400, "invalid_request")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise HTTPError(415, "unsupported_media_type")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1:
            raise HTTPError(400, "invalid_request")
        raw_length = lengths[0]
        if raw_length is None:
            raise HTTPError(411, "length_required")
        try:
            length = int(raw_length, 10)
        except ValueError as exc:
            raise HTTPError(400, "invalid_request") from exc
        if length < 0:
            raise HTTPError(400, "invalid_request")
        if length > self.server.max_body_bytes:
            raise HTTPError(413, "request_too_large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise HTTPError(400, "invalid_request")
        decoded = raw.decode("utf-8", "strict")
        data = json.loads(decoded, object_pairs_hook=_unique_object)
        if not isinstance(data, dict):
            raise HTTPError(400, "invalid_request")
        return data

    @staticmethod
    def _bounded_string(value: Any, maximum: int) -> str:
        if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
            raise HTTPError(400, "invalid_request")
        if "\0" in value or "\r" in value or "\n" in value:
            raise HTTPError(400, "invalid_request")
        return value

    def _validate_values(self, value: Any) -> list[str]:
        if not isinstance(value, list) or not value or len(value) > self.server.max_values:
            raise HTTPError(400, "invalid_request")
        return [self._bounded_string(item, self.server.max_value_bytes) for item in value]

    @staticmethod
    def _validate_session_result(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"label", "keys"}:
            raise RuntimeError("unsafe session response")
        label, keys = value["label"], value["keys"]
        if not isinstance(label, str) or len(label.encode("utf-8")) > 256:
            raise RuntimeError("unsafe session response")
        return {"label": label, "keys": _Handler._validate_key_list(keys)}

    @staticmethod
    def _validate_submit_result(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"added"}:
            raise RuntimeError("unsafe submit response")
        return {"added": _Handler._validate_key_list(value["added"])}

    @staticmethod
    def _validate_key_list(value: Any) -> list[str]:
        if not isinstance(value, list) or not value or len(value) > 64:
            raise RuntimeError("unsafe key list")
        if any(not isinstance(key, str) or not _ENV_KEY.fullmatch(key) for key in value):
            raise RuntimeError("unsafe key list")
        if len(set(value)) != len(value):
            raise RuntimeError("unsafe key list")
        return list(value)

    def _send_file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            return
        self._send(HTTPStatus.OK, body, content_type)

    def _json(self, status: int, payload: Any) -> None:
        try:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            return
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str) -> None:
        self._json(status, {"error": code})

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    do_PUT = do_HEAD
    do_DELETE = do_HEAD
    do_PATCH = do_HEAD
    do_OPTIONS = do_HEAD
