import ipaddress
import re
from itertools import islice
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from app.config import get_settings


class ParseError(ValueError):
    """Raised when an uploaded report cannot be parsed."""


_FIRST_ELEMENT = re.compile(r"<[A-Za-z_]")
_ANY_DOCTYPE = re.compile(r"<!DOCTYPE[^>]*>?", re.IGNORECASE)
_BARE_DOCTYPE = re.compile(r"<!DOCTYPE\s+[A-Za-z_][\w.:-]*\s*>")


def _check_prolog(raw: str | bytes) -> None:
    """Only a bare `<!DOCTYPE name>` (what Nmap writes) is allowed. Any internal subset
    ([...]) or SYSTEM/PUBLIC identifier is refused. Only the prolog is inspected."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    first = _FIRST_ELEMENT.search(text)
    prolog = text[: first.start()] if first else text
    for m in _ANY_DOCTYPE.finditer(prolog):
        if not _BARE_DOCTYPE.fullmatch(m.group()):
            raise ParseError("unsafe XML rejected: only a bare <!DOCTYPE name> is allowed")


def parse_xml(raw: str | bytes) -> Element:
    """Parse XML with defusedxml.

    Real Nmap output starts with a bare `<!DOCTYPE nmaprun>`, so a DOCTYPE itself must be allowed.
    The attacks are blocked separately: entity declarations (XXE, billion laughs) and external
    DTD/entity references are both rejected.
    """
    _check_prolog(raw)
    try:
        root = SafeET.fromstring(raw, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ParseError(f"unsafe XML rejected: {exc}") from exc
    except SafeET.ParseError as exc:
        raise ParseError(f"malformed XML: {exc}") from exc
    limit = get_settings().max_xml_elements
    if sum(1 for _ in islice(root.iter(), limit + 1)) > limit:
        raise ParseError(f"XML has more than {limit} elements")
    return root


def to_float(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def valid_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None
