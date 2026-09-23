from __future__ import annotations

import json
import socket
import ssl

import pytest

import scripts.external_probe as probe


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _addrinfo(*addresses: str):
    records = []
    for address in addresses:
        if ":" in address:
            records.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443, 0, 0)))
        else:
            records.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443)))
    return records


def _payload() -> bytes:
    return json.dumps(
        {
            "vantage": {"kind": "external", "id": "probe-eu-1"},
            "target": {"host": "target.example", "port": 18443},
            "reachable": True,
            "observed_at": "2026-09-23T00:00:00Z",
        }
    ).encode()


def test_resolver_rejects_entire_answer_if_any_address_is_not_global(monkeypatch):
    monkeypatch.setattr(
        probe.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _addrinfo(PUBLIC_V4, "127.0.0.1"),
    )
    monkeypatch.setattr(
        probe.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("transport must not connect after an unsafe DNS answer"),
    )

    with pytest.raises(probe.ProbeError, match="non-global"):
        probe.request_external_probe(
            "https://probe.example/check",
            target_host="target.example",
            target_port=18443,
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "2001:db8::1",
        "fc00::1",
        "fe80::1",
    ],
)
def test_resolver_rejects_every_non_global_address_class(monkeypatch, address):
    monkeypatch.setattr(probe.socket, "getaddrinfo", lambda *_args, **_kwargs: _addrinfo(address))

    with pytest.raises(probe.ProbeError, match="non-global"):
        probe.request_external_probe(
            "https://probe.example/check",
            target_host="target.example",
            target_port=18443,
        )


def test_pinned_connection_uses_validated_ip_but_original_hostname_for_tls(monkeypatch):
    raw_socket = object()
    tls_socket = object()
    calls = {}

    def create_connection(address, timeout, source_address=None):
        calls["connect"] = (address, timeout, source_address)
        return raw_socket

    class FakeContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(self, sock, *, server_hostname):
            calls["tls"] = (sock, server_hostname)
            return tls_socket

    monkeypatch.setattr(probe.socket, "create_connection", create_connection)
    connection = probe._PinnedHTTPSConnection(
        "probe.example",
        PUBLIC_V4,
        443,
        timeout=4.5,
        context=FakeContext(),
    )

    connection.connect()

    assert calls["connect"] == ((PUBLIC_V4, 443), 4.5, None)
    assert calls["tls"] == (raw_socket, "probe.example")
    assert connection.sock is tls_socket


def test_default_transport_ignores_proxies_pins_dns_answer_and_rejects_redirect(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:8080")
    monkeypatch.setattr(
        probe.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _addrinfo(PUBLIC_V4, PUBLIC_V6),
    )
    calls = {}

    class Response:
        status = 302
        reason = "Found"

        def read(self, _limit):
            pytest.fail("redirect response body must not be consumed")

    class Connection:
        def __init__(self, hostname, pinned_ip, port, *, timeout, context):
            calls["init"] = (hostname, pinned_ip, port, timeout, context)

        def request(self, method, target, *, headers):
            calls["request"] = (method, target, headers)

        def getresponse(self):
            return Response()

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(probe, "_PinnedHTTPSConnection", Connection)

    with pytest.raises(probe.ProbeError, match="redirects are not allowed"):
        probe.request_external_probe(
            "https://probe.example/check?region=eu",
            target_host="target.example",
            target_port=18443,
            timeout=4.5,
        )

    assert calls["init"][:4] == ("probe.example", PUBLIC_V4, 443, 4.5)
    assert calls["request"][0] == "GET"
    assert calls["request"][1] == "/check?region=eu&host=target.example&port=18443"
    assert calls["closed"] is True


def test_injected_fetch_keeps_request_contract_without_using_dns(monkeypatch):
    monkeypatch.setattr(
        probe.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("injected fetch must remain isolated from the default transport"),
    )
    seen = {}

    def fetch(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return _payload()

    result = probe.request_external_probe(
        "https://probe.example/check",
        target_host="target.example",
        target_port=18443,
        timeout=2.0,
        fetch=fetch,
    )

    assert result.reachable is True
    assert seen == {
        "url": "https://probe.example/check?host=target.example&port=18443",
        "timeout": 2.0,
    }
