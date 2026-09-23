#!/usr/bin/env python3
"""Client and response validation for an explicitly remote reachability probe."""

from __future__ import annotations

import datetime as dt
import argparse
import http.client
import ipaddress
import json
import math
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


class ProbeError(ValueError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    reachable: bool
    vantage_id: str
    target_host: str
    target_port: int
    observed_at: dt.datetime
    detail: str | None = None


def _resolve_global_ip(hostname: str, port: int) -> str:
    """Resolve once, reject the whole answer on any non-global address, and pin one IP."""
    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise ProbeError(f"external probe service DNS lookup failed: {exc}") from exc

    addresses: list[str] = []
    for family, _type, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            raise ProbeError("external probe service DNS returned an invalid address")
        address = sockaddr[0]
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ProbeError("external probe service DNS returned an invalid address") from exc
        if not parsed_address.is_global or parsed_address.is_multicast:
            raise ProbeError("external probe service DNS returned a non-global address")
        normalized = str(parsed_address)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise ProbeError("external probe service DNS returned no addresses")
    return addresses[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while retaining the URL hostname for TLS."""

    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._tls_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
            None,
        )
        try:
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


def _fetch_pinned_https(
    request: urllib.request.Request,
    timeout: float,
    *,
    hostname: str,
    port: int,
) -> bytes:
    """Fetch directly without proxy or redirect support after validating DNS."""
    pinned_ip = _resolve_global_ip(hostname, port)
    parsed = urllib.parse.urlsplit(request.full_url)
    target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection = _PinnedHTTPSConnection(
        hostname,
        pinned_ip,
        port,
        timeout=timeout,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(request.get_method(), target, headers=dict(request.header_items()))
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ProbeError("external probe redirects are not allowed")
        if not 200 <= response.status < 300:
            raise ProbeError(f"external probe service returned HTTP {response.status}")
        return response.read(65537)
    finally:
        connection.close()


def parse_probe_response(payload: Any, *, expected_host: str, expected_port: int) -> ProbeResult:
    """Validate remote-vantage metadata and an exact target echo.

    A local socket test is intentionally not accepted as external evidence.
    Authentication of the probe service remains the caller's transport/config
    responsibility.
    """
    if not isinstance(payload, dict):
        raise ProbeError("probe response must be an object")
    vantage = payload.get("vantage")
    target = payload.get("target")
    if not isinstance(vantage, dict) or vantage.get("kind") != "external":
        raise ProbeError("probe response lacks an explicit external vantage")
    vantage_id = vantage.get("id")
    if not isinstance(vantage_id, str) or not vantage_id.strip() or vantage_id == expected_host:
        raise ProbeError("probe vantage id is missing or aliases the target")
    if not isinstance(target, dict):
        raise ProbeError("probe response lacks target metadata")
    if target.get("host") != expected_host or target.get("port") != expected_port:
        raise ProbeError("probe response target does not match the requested endpoint")
    reachable = payload.get("reachable")
    if not isinstance(reachable, bool):
        raise ProbeError("probe reachable field must be boolean")
    observed = payload.get("observed_at")
    if not isinstance(observed, str):
        raise ProbeError("probe response lacks observed_at")
    try:
        timestamp = dt.datetime.fromisoformat(observed.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProbeError("probe observed_at is invalid") from exc
    if timestamp.tzinfo is None:
        raise ProbeError("probe observed_at must include a timezone")
    detail = payload.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise ProbeError("probe detail must be a string")
    return ProbeResult(reachable, vantage_id, expected_host, expected_port, timestamp, detail)


def request_external_probe(
    service_url: str,
    *,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
    fetch: Callable[[urllib.request.Request, float], bytes] | None = None,
) -> ProbeResult:
    """Ask a configured non-local HTTPS service to probe the endpoint."""
    parsed = urllib.parse.urlsplit(service_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProbeError("external probe service must use HTTPS")
    service_hostname = parsed.hostname
    if parsed.username is not None or parsed.password is not None:
        raise ProbeError("external probe service URL may not contain credentials")
    if parsed.fragment:
        raise ProbeError("external probe service URL may not contain a fragment")
    try:
        service_port = parsed.port
    except ValueError as exc:
        raise ProbeError("external probe service URL has an invalid port") from exc
    if service_port is not None and not 1 <= service_port <= 65535:
        raise ProbeError("external probe service URL has an invalid port")
    if service_hostname.lower().rstrip(".") == "localhost":
        raise ProbeError("external probe service may not be localhost")
    if not 1 <= target_port <= 65535:
        raise ProbeError("target_port must be in 1..65535")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
        raise ProbeError("timeout must be finite and in (0, 60]")
    try:
        service_ip = ipaddress.ip_address(service_hostname)
    except ValueError:
        service_ip = None
    if service_ip is not None and (not service_ip.is_global or service_ip.is_multicast):
        raise ProbeError("external probe service may not use a non-global address")
    query = urllib.parse.urlencode({"host": target_host, "port": target_port})
    separator = "&" if parsed.query else "?"
    request = urllib.request.Request(f"{service_url}{separator}{query}", headers={"Accept": "application/json"})

    def default_fetch(req: urllib.request.Request, limit: float) -> bytes:
        return _fetch_pinned_https(
            req,
            limit,
            hostname=service_hostname,
            port=service_port or 443,
        )

    try:
        body = (fetch or default_fetch)(request, timeout)
        if len(body) > 65536:
            raise ProbeError("probe response is too large")
        payload = json.loads(body)
    except ProbeError:
        raise
    except Exception as exc:
        raise ProbeError(f"external probe request failed: {exc}") from exc
    return parse_probe_response(payload, expected_host=target_host, expected_port=target_port)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Request a probe from an explicitly external HTTPS service")
    parser.add_argument("--service-url", required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = request_external_probe(
            args.service_url,
            target_host=args.target_host,
            target_port=args.target_port,
            timeout=args.timeout,
        )
    except ProbeError as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps({
        "reachable": result.reachable,
        "vantage_id": result.vantage_id,
        "target_host": result.target_host,
        "target_port": result.target_port,
        "observed_at": result.observed_at.isoformat(),
        "detail": result.detail,
    }, sort_keys=True))
    return 0 if result.reachable else 1


if __name__ == "__main__":
    raise SystemExit(main())
