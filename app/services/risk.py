"""CVSS normalisation and risk scoring."""

SEVERITY_DEFAULT_SCORE = {  # used only when a scanner gives a label but no number
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "moderate": 5.5,
    "low": 2.5,
    "info": 0.0,
    "informational": 0.0,
    "none": 0.0,
}


def severity_from_score(score: float | None) -> str | None:
    """CVSS v3 qualitative rating scale."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalize_cvss(score: float | None, severity: str | None) -> tuple[float | None, str | None]:
    """Clamp to 0-10; derive a score from a severity label if needed; derive the label."""
    if score is not None:
        score = round(min(10.0, max(0.0, float(score))), 1)
    elif severity and severity.lower() in SEVERITY_DEFAULT_SCORE:
        score = SEVERITY_DEFAULT_SCORE[severity.lower()]
    return score, severity_from_score(score)


def risk_score(cvss: float | None, epss: float | None, in_kev: bool) -> float:
    """Prioritisation score on a 0-10 scale.

    Starts from CVSS (severity if exploited), then adds +1.0 if the CVE is on CISA's Known
    Exploited Vulnerabilities list and up to +1.0 scaled by EPSS (probability of
    exploitation in the next 30 days). Capped at 10.
    """
    base = cvss or 0.0
    bonus = (1.0 if in_kev else 0.0) + max(0.0, min(1.0, epss or 0.0))
    return round(min(10.0, base + bonus), 1)
