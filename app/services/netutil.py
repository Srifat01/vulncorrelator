"""Small, pure helpers for addresses and names."""

import ipaddress
import re

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# Shared virtual MACs (VRRP/HSRP/GLBP): several machines legitimately answer with the same one,
# so they must never be used to merge hosts.
_SHARED_MAC_PREFIXES = ("00:00:5e:00:01", "00:00:5e:00:02", "00:00:0c:07:ac", "00:07:b4:00", "00:00:0c:9f:f")


def normalize_mac(raw: str | None) -> str | None:
    """Canonical lowercase colon form, or None if the value can't identify a single host."""
    if not raw:
        return None
    s = raw.strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", s):  # aabbccddeeff
        s = ":".join(s[i : i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.match(s):
        return None
    if int(s[:2], 16) & 1:  # multicast/broadcast bit
        return None
    if s == "00:00:00:00:00:00" or s.startswith(_SHARED_MAC_PREFIXES):
        return None
    return s


def normalize_hostname(raw: str | None) -> str | None:
    if not raw:
        return None
    h = raw.strip().lower().rstrip(".")
    return h or None


def short_hostname(h: str) -> str:
    return h.split(".", 1)[0]


def is_fqdn(h: str | None) -> bool:
    return bool(h) and "." in h and not re.fullmatch(r"[\d.]+", h)


def hostnames_conflict(a: str | None, b: str | None) -> bool:
    """True only when both names are known and clearly refer to different machines."""
    a, b = normalize_hostname(a), normalize_hostname(b)
    if not a or not b:
        return False
    if is_fqdn(a) and is_fqdn(b):
        return a != b
    return short_hostname(a) != short_hostname(b)


def is_public_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global
