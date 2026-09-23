from __future__ import annotations

import http.client
import json
import socket
import ssl
import subprocess
import threading
import time

import pytest

from secure_env_ingress.server import HTTPError, HTTPSFormServer


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.used = False

    def session(self, token: str, init_data: str) -> dict:
        self.calls.append(("session", token, init_data))
        if token != "capability":
            raise HTTPError(410, "unavailable")
        return {"label": "Test profile", "keys": ["API_KEY", "SECOND_KEY"]}

    def submit(self, token: str, init_data: str, values: list[str]) -> dict:
        self.calls.append(("submit", token, init_data, values))
        if token != "capability" or self.used:
            raise HTTPError(410, "unavailable")
        self.used = True
        return {"added": ["API_KEY", "SECOND_KEY"]}


@pytest.fixture(scope="module")
def tls_context(tmp_path_factory: pytest.TempPathFactory) -> ssl.SSLContext:
    directory = tmp_path_factory.mktemp("tls")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


@pytest.fixture
def running_server(tls_context: ssl.SSLContext):
    backend = FakeBackend()
    server = HTTPSFormServer(("127.0.0.1", 0), tls_context, backend)
    thread = server.start()
    yield server, backend, thread
    server.stop()


def _request(server: HTTPSFormServer, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        "127.0.0.1", server.server_address[1], context=context, timeout=3
    )
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    connection.close()
    return result


def _json_request(server: HTTPSFormServer, path: str, payload: object):
    body = json.dumps(payload, ensure_ascii=False).encode()
    return _request(server, "POST", path, body, {"Content-Type": "application/json"})


def test_https_get_serves_first_party_accessible_assets_without_backend_call(running_server) -> None:
    server, backend, _ = running_server
    status, headers, body = _request(server, "GET", "/e")
    assert status == 200
    assert b'<html lang="en">' in body
    assert b'aria-live="polite"' in body
    assert b'type="password"' not in body  # fields are created only from server-provided keys
    assert backend.calls == []
    assert headers["cache-control"] == "no-store, max-age=0"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"

    css = _request(server, "GET", "/static/entry.css")
    script = _request(server, "GET", "/static/entry.js")
    assert css[0] == script[0] == 200
    assert b"localStorage" not in script[2]
    assert b"sessionStorage" not in script[2]
    assert b"tgWebAppData" in script[2]


def test_session_and_submit_use_backend_key_order_and_never_echo_values(running_server) -> None:
    server, backend, _ = running_server
    status, _, body = _json_request(
        server, "/session", {"token": "capability", "initData": "signed-data"}
    )
    assert status == 200
    assert json.loads(body) == {"label": "Test profile", "keys": ["API_KEY", "SECOND_KEY"]}

    secret = "fixture-super-secret"
    status, _, body = _json_request(
        server,
        "/submit",
        {"token": "capability", "initData": "signed-data", "values": [secret, "other"]},
    )
    assert status == 200
    assert json.loads(body) == {"added": ["API_KEY", "SECOND_KEY"]}
    assert secret.encode() not in body
    assert backend.calls[-1] == (
        "submit", "capability", "signed-data", [secret, "other"]
    )

    status, _, body = _json_request(
        server, "/submit", {"token": "capability", "initData": "", "values": ["x", "y"]}
    )
    assert status == 410
    assert json.loads(body) == {"error": "unavailable"}


def test_rejects_unsafe_backend_responses_without_echoing_them(
    tls_context: ssl.SSLContext,
) -> None:
    secret = "backend-must-not-echo-this"

    class UnsafeBackend(FakeBackend):
        def session(self, token: str, init_data: str) -> dict:
            return {"label": "profile", "keys": ["NOT A VALID KEY"]}

        def submit(self, token: str, init_data: str, values: list[str]) -> dict:
            return {"added": ["API_KEY"], "value": secret}

    server = HTTPSFormServer(("127.0.0.1", 0), tls_context, UnsafeBackend())
    server.start()
    try:
        for path, payload in (
            ("/session", {"token": "capability", "initData": ""}),
            ("/submit", {"token": "capability", "initData": "", "values": ["x"]}),
        ):
            status, _, body = _json_request(server, path, payload)
            assert status == 500
            assert json.loads(body) == {"error": "internal_error"}
            assert secret.encode() not in body
    finally:
        server.stop()


def test_rejects_unknown_duplicate_malformed_and_unsafe_input(running_server) -> None:
    server, backend, _ = running_server
    cases = [
        (b'{"token":"capability","token":"again","initData":""}', 400),
        (b'{"token":"capability","initData":"","extra":1}', 400),
        (b'\xff', 400),
        (json.dumps({"token": "capability", "initData": "", "values": ["line\nfeed", "x"]}).encode(), 400),
        (json.dumps({"token": "capability", "initData": "", "values": ["nul\u0000byte", "x"]}).encode(), 400),
    ]
    prior = list(backend.calls)
    for body, expected in cases:
        status, headers, response = _request(
            server, "POST", "/submit", body, {"Content-Type": "application/json"}
        )
        assert status == expected
        assert headers["cache-control"].startswith("no-store")
        assert b"line" not in response and b"nul" not in response
    assert backend.calls == prior


def test_enforces_content_type_body_limit_methods_and_paths(running_server) -> None:
    server, _, _ = running_server
    assert _request(server, "POST", "/session", b"{}", {"Content-Type": "text/plain"})[0] == 415
    assert _request(
        server, "POST", "/session", b" " * (server.max_body_bytes + 1),
        {"Content-Type": "application/json"},
    )[0] == 413
    assert _request(server, "PUT", "/e")[0] == 405
    assert _request(server, "GET", "/unknown")[0] == 404


def test_rejects_transfer_encoding_even_with_content_length(running_server) -> None:
    server, backend, _ = running_server
    body = b'{"token":"capability","initData":""}'
    status, _, _ = _request(
        server,
        "POST",
        "/session",
        body,
        {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Transfer-Encoding": "chunked",
        },
    )
    assert status == 400
    assert backend.calls == []


def test_rate_limits_have_bounded_memory(tls_context: ssl.SSLContext) -> None:
    backend = FakeBackend()
    server = HTTPSFormServer(
        ("127.0.0.1", 0), tls_context, backend, per_ip_limit=2, per_capability_limit=2,
        rate_window_seconds=60, max_rate_entries=4,
    )
    server.start()
    try:
        assert _json_request(server, "/session", {"token": "capability", "initData": ""})[0] == 200
        assert _json_request(server, "/session", {"token": "capability", "initData": ""})[0] == 200
        assert _json_request(server, "/session", {"token": "capability", "initData": ""})[0] == 429
        assert server.rate_entry_count <= 4
    finally:
        server.stop()


def test_incomplete_tls_handshake_does_not_block_valid_client(
    tls_context: ssl.SSLContext,
) -> None:
    server = HTTPSFormServer(("127.0.0.1", 0), tls_context, FakeBackend())
    server.request_timeout_seconds = .5
    server.start()
    slow = socket.create_connection(
        (str(server.server_address[0]), int(server.server_address[1])), timeout=1
    )
    try:
        slow.sendall(b"\x16")
        time.sleep(.1)
        started = time.monotonic()
        status, _, _ = _request(server, "GET", "/e")
        assert status == 200
        assert time.monotonic() - started < 1
    finally:
        slow.close()
        server.stop()


def test_ipv6_literal_listener_when_loopback_is_available(
    tls_context: ssl.SSLContext,
) -> None:
    if not socket.has_ipv6:
        pytest.skip("Python has no IPv6 support")
    try:
        server = HTTPSFormServer(("::1", 0), tls_context, FakeBackend())
    except OSError:
        pytest.skip("IPv6 loopback is unavailable")
    server.start()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            "::1", server.server_address[1], context=context, timeout=3
        )
        connection.request("GET", "/e")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
    finally:
        server.stop()


def test_stop_closes_listener_and_joins_thread(running_server) -> None:
    server, _, thread = running_server
    port = server.server_address[1]
    assert isinstance(thread, threading.Thread) and thread.is_alive()
    server.stop()
    thread.join(timeout=2)
    assert not thread.is_alive()
    deadline = time.monotonic() + 2
    while True:
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.1)
        except OSError:
            break
        else:
            connection.close()
        assert time.monotonic() < deadline, "listener remained reachable after stop()"


def test_server_suppresses_internal_request_error_output(
    tls_context: ssl.SSLContext, capsys: pytest.CaptureFixture[str]
) -> None:
    server = HTTPSFormServer(("127.0.0.1", 0), tls_context, FakeBackend())
    try:
        try:
            raise RuntimeError("sensitive diagnostic")
        except RuntimeError:
            server.handle_error(server.socket, ("127.0.0.1", 12345))
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
    finally:
        server.stop()
