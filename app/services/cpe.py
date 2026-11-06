"""CPE parsing and product-name -> CPE mapping.

Scanners disagree about naming ("Apache httpd", "apache:http_server", "www"). We reduce
everything to a (vendor, product, version) triple so findings can be matched against
the vulnerability catalog and deduplicated across tools.
"""

import re
from dataclasses import dataclass
from urllib.parse import unquote

_UNESCAPED_COLON = re.compile(r"(?<!\\):")


@dataclass(frozen=True)
class Cpe:
    part: str  # a=application, o=os, h=hardware
    vendor: str
    product: str
    version: str | None

    @property
    def key(self) -> str:
        return f"{self.vendor}:{self.product}"


def _clean(value: str | None) -> str | None:
    if value is None or value in ("", "*", "-"):
        return None
    return unquote(value.replace("\\", "")).lower()


def parse_cpe(raw: str | None) -> Cpe | None:
    """Parse CPE 2.2 URI (cpe:/a:vendor:product:version) or 2.3 formatted-string form."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("cpe:2.3:"):
        parts = _UNESCAPED_COLON.split(raw)[2:]
    elif raw.startswith("cpe:/"):
        parts = raw[len("cpe:/") :].split(":")
    else:
        return None
    if len(parts) < 3:
        return None
    part, vendor, product = parts[0], _clean(parts[1]), _clean(parts[2])
    if part not in ("a", "o", "h") or not vendor or not product:
        return None
    version = _clean(parts[3]) if len(parts) > 3 else None
    return Cpe(part, vendor, product, version)


# lowercase substring found in a scanner's product string -> (vendor, product)
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "apache log4j": ("apache", "log4j"),
    "log4j": ("apache", "log4j"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("beasts", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "openssl": ("openssl", "openssl"),
    "samba": ("samba", "samba"),
    "polkit": ("polkit_project", "polkit"),
    "sudo": ("sudo_project", "sudo"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
}


def guess_vendor_product(product: str | None) -> tuple[str, str] | None:
    if not product:
        return None
    p = product.lower()
    # longest alias first so "apache http server" wins over a shorter overlap
    for alias in sorted(PRODUCT_ALIASES, key=len, reverse=True):
        if alias in p:
            return PRODUCT_ALIASES[alias]
    return None


# Scanner-specific service names -> a common vocabulary
SERVICE_ALIASES = {
    "www": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "https-alt": "https",
    "ssl/http": "https",
    "ssl/https": "https",
    "microsoft-ds": "smb",
    "cifs": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "ms-sql-s": "mssql",
    "postgres": "postgresql",
    "ssh": "ssh",
}


def normalize_service_name(name: str | None) -> str | None:
    if not name:
        return None
    n = name.strip().lower().rstrip("?")
    if n.startswith("ssl|"):
        n = "ssl/" + n[4:]
    return SERVICE_ALIASES.get(n, n) or None
