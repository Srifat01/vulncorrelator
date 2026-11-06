import json

from pydantic import ValidationError

from app.parsers.base import ParseError
from app.parsers.nessus import parse_nessus
from app.parsers.nmap import parse_nmap
from app.schemas import ReportIn

FORMATS = ("json", "nmap", "nessus")


def parse_json(raw: str | bytes) -> ReportIn:
    try:
        return ReportIn.model_validate(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise ParseError(f"malformed JSON: {exc}") from exc
    except ValidationError as exc:
        raise ParseError(f"invalid report: {exc.errors(include_url=False, include_input=False)}") from exc


def parse_report(fmt: str, raw: str | bytes) -> ReportIn:
    parsers = {"json": parse_json, "nmap": parse_nmap, "nessus": parse_nessus}
    if fmt not in parsers:
        raise ParseError(f"unsupported format {fmt!r}; expected one of {FORMATS}")
    try:
        return parsers[fmt](raw)
    except ValidationError as exc:
        raise ParseError(f"invalid {fmt} data: {exc.errors(include_url=False, include_input=False)}") from exc


__all__ = ["ParseError", "parse_report", "FORMATS"]
