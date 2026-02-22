"""Local-network access policy helpers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .const import DEFAULT_ALLOWED_CIDRS

_SEPARATOR_PATTERN = re.compile(r"[\s,;]+")
_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr, strict=False) for cidr in DEFAULT_ALLOWED_CIDRS
)


def parse_allowed_cidrs_text(cidr_text: str) -> list[str]:
    """Parse CSV/text input into normalized CIDR strings."""
    raw_parts = [part.strip() for part in _SEPARATOR_PATTERN.split(cidr_text) if part.strip()]
    return normalize_allowed_cidrs(raw_parts)


def normalize_allowed_cidrs(cidrs: Iterable[str]) -> list[str]:
    """Validate CIDRs and ensure all networks are RFC1918 subnets."""
    normalized: list[str] = []
    seen: set[str] = set()

    for cidr in cidrs:
        if not isinstance(cidr, str):
            raise ValueError("CIDR value must be a string")
        candidate = cidr.strip()
        if not candidate:
            continue

        network = ipaddress.ip_network(candidate, strict=False)
        if not _is_rfc1918_subnet(network):
            raise ValueError("Only RFC1918 networks are allowed")

        network_text = str(network)
        if network_text not in seen:
            seen.add(network_text)
            normalized.append(network_text)

    if not normalized:
        raise ValueError("At least one RFC1918 CIDR must be provided")

    return normalized


def is_remote_allowed(remote: str | None, allowed_cidrs: Iterable[str]) -> bool:
    """Check whether remote IP is within allowed CIDR ranges."""
    if not remote:
        return False

    candidate = remote.split("%", maxsplit=1)[0]
    try:
        remote_ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    for cidr in allowed_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if remote_ip in network:
            return True

    return False


def _is_rfc1918_subnet(network: ipaddress._BaseNetwork) -> bool:
    """Return True when network is fully contained in RFC1918 address space."""
    return any(network.subnet_of(rfc1918) for rfc1918 in _RFC1918_NETWORKS)
