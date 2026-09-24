"""Thread-safe, memory-only storage for one-time ingress capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path
from typing import Callable, Literal, TypeAlias


Mode: TypeAlias = Literal["browser", "mini"]
TargetId: TypeAlias = tuple[int, int]


class InvalidTTL(ValueError):
    """Raised when a capability TTL is outside the permitted range."""


@dataclass(frozen=True, slots=True)
class IssuedCapability:
    """A newly issued bearer capability.

    The token is deliberately excluded from ``repr`` so logging this object does
    not disclose it. The store itself retains only the token's SHA-256 digest.
    """

    token: str = field(repr=False)
    mode: Mode
    group_id: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class CapabilityClaim:
    """Non-secret metadata associated with a capability."""

    mode: Mode
    group_id: str
    platform: str
    user_id: str | int
    hermes_home: Path
    profile_name: str
    allowed_keys: tuple[str, ...]
    target_id: TargetId
    created_at: float
    expires_at: float


# Metadata returned by a non-consuming lookup and by a successful consume is
# intentionally the same safe, token-free object.
CapabilityMetadata = CapabilityClaim


@dataclass(frozen=True, slots=True)
class _Record:
    claim: CapabilityClaim


class CapabilityStore:
    """Keep at most one active browser/mini capability pair in process memory."""

    MIN_TTL_SECONDS = 120
    MAX_TTL_SECONDS = 600

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._records: dict[bytes, _Record] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(token: str) -> bytes | None:
        if not isinstance(token, str):
            return None
        return hashlib.sha256(token.encode("utf-8")).digest()

    @staticmethod
    def _home_identity(hermes_home: Path | str) -> Path:
        return Path(hermes_home).expanduser().absolute()

    def _purge_expired_locked(self, now: float) -> None:
        expired = [digest for digest, record in self._records.items() if now >= record.claim.expires_at]
        for digest in expired:
            self._records.pop(digest, None)

    def _find_locked(self, candidate: bytes) -> tuple[bytes, _Record] | None:
        # There are no more than two records. Scanning permits a constant-time
        # digest comparison rather than comparing bearer strings directly.
        found: tuple[bytes, _Record] | None = None
        for digest, record in self._records.items():
            if hmac.compare_digest(digest, candidate):
                found = (digest, record)
        return found

    def issue_pair(
        self,
        *,
        platform: str,
        user_id: str | int,
        hermes_home: Path | str,
        profile_name: str,
        allowed_keys: tuple[str, ...],
        target_id: TargetId,
        ttl_seconds: int,
    ) -> tuple[IssuedCapability, IssuedCapability]:
        """Issue distinct mode-bound siblings, invalidating any prior pair."""
        if type(ttl_seconds) is not int or not self.MIN_TTL_SECONDS <= ttl_seconds <= self.MAX_TTL_SECONDS:
            raise InvalidTTL(f"ttl_seconds must be {self.MIN_TTL_SECONDS}..{self.MAX_TTL_SECONDS}")

        browser_token = secrets.token_urlsafe(32)
        mini_token = secrets.token_urlsafe(32)
        while mini_token == browser_token:
            mini_token = secrets.token_urlsafe(32)

        browser_digest = self._digest(browser_token)
        mini_digest = self._digest(mini_token)
        if browser_digest is None or mini_digest is None:
            raise RuntimeError("capability generation failed")
        group_id = secrets.token_hex(16)
        now = self._clock()
        expires_at = now + ttl_seconds
        home = self._home_identity(hermes_home)
        keys = tuple(allowed_keys)
        target = tuple(target_id)
        if len(target) != 2:
            raise ValueError("target_id must contain exactly two integers")
        normalized_target: TargetId = (target[0], target[1])

        def claim(mode: Mode) -> CapabilityClaim:
            return CapabilityClaim(
                mode=mode,
                group_id=group_id,
                platform=platform,
                user_id=user_id,
                hermes_home=home,
                profile_name=profile_name,
                allowed_keys=keys,
                target_id=normalized_target,
                created_at=now,
                expires_at=expires_at,
            )

        with self._lock:
            self._records.clear()
            self._records[browser_digest] = _Record(claim("browser"))
            self._records[mini_digest] = _Record(claim("mini"))

        return (
            IssuedCapability(browser_token, "browser", group_id, expires_at),
            IssuedCapability(mini_token, "mini", group_id, expires_at),
        )

    def peek(self, token: str) -> CapabilityMetadata | None:
        """Return unexpired token-free metadata without consuming the pair."""
        candidate = self._digest(token)
        if candidate is None:
            return None
        with self._lock:
            self._purge_expired_locked(self._clock())
            found = self._find_locked(candidate)
            return found[1].claim if found is not None else None

    def lookup(self, token: str) -> CapabilityMetadata | None:
        """Alias for :meth:`peek`, for backend lookup call sites."""
        return self.peek(token)

    def consume(
        self,
        token: str,
        *,
        mode: Mode,
        platform: str,
        user_id: str | int,
        hermes_home: Path | str,
        profile_name: str | None = None,
        target_id: TargetId | None = None,
        allowed_keys: tuple[str, ...] | None = None,
    ) -> CapabilityClaim | None:
        """Atomically validate and consume a capability and its sibling."""
        candidate = self._digest(token)
        if candidate is None:
            return None
        home = self._home_identity(hermes_home)
        with self._lock:
            self._purge_expired_locked(self._clock())
            found = self._find_locked(candidate)
            if found is None:
                return None
            claim = found[1].claim
            if (
                claim.mode != mode
                or claim.platform != platform
                or claim.user_id != user_id
                or claim.hermes_home != home
                or (profile_name is not None and claim.profile_name != profile_name)
                or (target_id is not None and claim.target_id != tuple(target_id))
                or (allowed_keys is not None and claim.allowed_keys != tuple(allowed_keys))
            ):
                return None
            sibling_digests = [
                digest
                for digest, record in self._records.items()
                if record.claim.group_id == claim.group_id
            ]
            for digest in sibling_digests:
                self._records.pop(digest, None)
            return claim

    def cancel(
        self,
        *,
        platform: str,
        user_id: str | int,
        hermes_home: Path | str,
        profile_name: str | None = None,
        target_id: TargetId | None = None,
    ) -> bool:
        """Cancel the active pair only when its owner context matches."""
        home = self._home_identity(hermes_home)
        with self._lock:
            self._purge_expired_locked(self._clock())
            if not self._records:
                return False
            claim = next(iter(self._records.values())).claim
            if (
                claim.platform != platform
                or claim.user_id != user_id
                or claim.hermes_home != home
                or (profile_name is not None and claim.profile_name != profile_name)
                or (target_id is not None and claim.target_id != tuple(target_id))
            ):
                return False
            self._records.clear()
            return True

    def clear(self) -> None:
        """Remove every in-memory capability during shutdown."""
        with self._lock:
            self._records.clear()

    @property
    def active_count(self) -> int:
        with self._lock:
            self._purge_expired_locked(self._clock())
            return len(self._records)
