"""Target validation and network safety policy for authorized assessments."""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _load_env_file() -> None:
    try:
        env_file = Path(__file__).resolve().parent.parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))
    except Exception:
        pass


_load_env_file()


@dataclass(frozen=True)
class TargetPolicy:
    """Safety policy applied before an assessment starts.

    Private/loopback/link-local targets are allowed by default for local/lab testing
    or authorized internal engagements (ALLOW_PRIVATE_TARGETS=1).
    """

    allow_private_targets: bool = False
    allow_non_default_ports: bool = True
    max_url_length: int = 2048

    @classmethod
    def from_environment(cls) -> "TargetPolicy":
        return cls(
            allow_private_targets=os.getenv("ALLOW_PRIVATE_TARGETS", "1").lower()
            in {"1", "true", "yes", "on"},
        )


def _is_forbidden_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any((
        ip.is_loopback,
        ip.is_private,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
    ))


def validate_target_url(target: str, policy: TargetPolicy | None = None) -> str:
    """Validate and normalize a client target before network activity.

    This deliberately rejects credentials in the URL, non-HTTP schemes,
    malformed ports and DNS names resolving to non-public addresses unless
    private-target mode is explicitly enabled.
    """
    policy = policy or TargetPolicy.from_environment()
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Target URL is required")
    if len(raw) > policy.max_url_length:
        raise ValueError("Target URL is too long")
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS targets are supported")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Target URL must contain a hostname and must not contain embedded credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port") from exc
    if not policy.allow_non_default_ports and port not in {None, 80, 443}:
        raise ValueError("Non-default target ports are disabled by policy")

    # Literal IPs can be checked without DNS. Hostnames are resolved now so a
    # public-looking hostname that points to localhost/private space is not
    # accidentally scanned.
    addresses: set[str] = set()
    try:
        literal = ipaddress.ip_address(parsed.hostname)
        addresses.add(str(literal))
    except ValueError:
        try:
            infos = socket.getaddrinfo(parsed.hostname, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"Could not resolve target hostname: {parsed.hostname}") from exc
        addresses.update(str(info[4][0]) for info in infos if info and info[4])

    if not addresses:
        raise ValueError("Target hostname did not resolve to an address")
    if not policy.allow_private_targets:
        forbidden = sorted(address for address in addresses if _is_forbidden_ip(address))
        if forbidden:
            raise ValueError(
                "Target resolves to a private, loopback, link-local, multicast, reserved, "
                "or unspecified address. Enable 'Allow private / local network targets' or set "
                "ALLOW_PRIVATE_TARGETS=1 for an authorized internal/lab assessment."
            )

    return raw.rstrip("/")


def same_origin(a: str, b: str) -> bool:
    """Compare HTTP(S) origins using scheme, hostname and effective port."""
    x, y = urlparse(a), urlparse(b)
    xp = x.port or (443 if x.scheme.lower() == "https" else 80)
    yp = y.port or (443 if y.scheme.lower() == "https" else 80)
    return (x.scheme.lower(), (x.hostname or "").lower(), xp) == (
        y.scheme.lower(), (y.hostname or "").lower(), yp
    )
