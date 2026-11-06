import ipaddress
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


class ParseError(ValueError):
    """Raised when an uploaded report cannot be parsed."""


def parse_xml(raw: str | bytes) -> Element:
    """Parse XML with defusedxml (blocks XXE, entity expansion bombs, DTD tricks)."""
    try:
        return SafeET.fromstring(raw, forbid_dtd=True)
    except DefusedXmlException as exc:
        raise ParseError(f"unsafe XML rejected: {exc}") from exc
    except SafeET.ParseError as exc:
        raise ParseError(f"malformed XML: {exc}") from exc


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
