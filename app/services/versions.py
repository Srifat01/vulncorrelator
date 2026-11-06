"""Lenient version comparison for software versions like 2.4.49, 7.2p2 or 1.0.1f."""

import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def parse_version(version: str) -> tuple[int, ...]:
    """Turn a version string into a comparable tuple.

    Numeric chunks stay numbers; an alphabetic chunk contributes the code of its first
    letter, so 1.0.1f < 1.0.1g and 7.2 < 7.2p1. This is a heuristic, not full semver/PEP 440.
    """
    out: list[int] = []
    for tok in _TOKEN.findall(version):
        out.append(int(tok) if tok.isdigit() else ord(tok[0].lower()))
    return tuple(out)


def version_matches(
    version: str,
    *,
    exact: list[str] | None = None,
    gte: str | None = None,
    gt: str | None = None,
    lte: str | None = None,
    lt: str | None = None,
) -> bool:
    if exact is not None and version in exact:
        return True
    bounds = (gte, gt, lte, lt)
    if all(b is None for b in bounds):
        return False  # only an exact list was given and it didn't match
    v = parse_version(version)
    if not v:
        return False
    if gte is not None and v < parse_version(gte):
        return False
    if gt is not None and v <= parse_version(gt):
        return False
    if lte is not None and v > parse_version(lte):
        return False
    if lt is not None and v >= parse_version(lt):
        return False
    return True
