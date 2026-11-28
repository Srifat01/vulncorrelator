"""Contextual risk model v2: independent, inspectable components - never a blind sum.

    severity        = CVSS base score / 10                                   (intrinsic severity)
    likelihood      = max(KEV floor if on CISA KEV, EPSS)                    (exploitation likelihood)
    exploitability  = CVSS v3 exploitability sub-score / max                 (exploit prerequisites)
    exposure        = reachability evidence for the service                  (environmental exposure)
    controls        = product of declared control multipliers                (available security controls)
    business        = asset criticality factor                               (business impact)
    attackability   = exposure x exploitability x controls
    threat          = sqrt(likelihood x attackability)
    impact          = w x severity + (1 - w) x business
    relevance       = attack-path position factor
    priority        = 10 x impact x threat x relevance                       (0-10)

`threat` is deliberately separate from `impact`, so "how bad if it happens" and "how likely is it to be used" can
be read independently. Every input that had to be assumed is listed under `data_quality`.
The score ranks work; it is not a probability and has not been calibrated against incident data.
"""

import math
from dataclasses import dataclass, field

from app.risk.config import RiskModelConfig
from app.services.cvss import parse_cvss3

FORMULA = (
    "priority = 10 * impact * relevance * sqrt(likelihood * attackability); "
    "impact = w*severity + (1-w)*business; attackability = exposure * exploitability * controls"
)


@dataclass
class RiskInputs:
    cvss_score: float | None
    cvss_vector: str | None
    cvss_source: str | None
    epss: float | None
    in_kev: bool
    kev_known: bool  # False when the KEV feed has never been synced (so "not on KEV" is unknown, not false)
    asset_criticality: int
    exposure_level: str
    controls: list[str] = field(default_factory=list)
    path_relevance: str = "not_on_path"


@dataclass
class RiskResult:
    score: float
    band: str
    threat: float
    components: dict
    data_quality: list[str]


def compute_risk(i: RiskInputs, cfg: RiskModelConfig) -> RiskResult:
    dq: list[str] = []

    sev = (i.cvss_score or 0.0) / 10
    if i.cvss_score is None:
        dq.append("no CVSS score: severity treated as 0")

    if i.in_kev:
        likelihood, basis = max(cfg.kev_likelihood_floor, i.epss or 0.0), "kev"
    elif i.epss is not None:
        likelihood, basis = i.epss, "epss"
    else:
        likelihood, basis = cfg.missing_epss_likelihood, "assumed_missing"
        dq.append(f"no EPSS value: exploitation likelihood ASSUMED to be {cfg.missing_epss_likelihood}")
    if not i.in_kev and not i.kev_known:
        dq.append("CISA KEV has not been synced: 'not exploited in the wild' is unknown, not established")

    cv = parse_cvss3(i.cvss_vector)
    if cv:
        exploitability, ex_assumed = cv.exploitability, False
    else:
        exploitability, ex_assumed = cfg.unknown_vector_exploitability, True
        dq.append("no CVSS v3 vector: exploit prerequisites ASSUMED")

    exposure = cfg.exposure.get(i.exposure_level, cfg.exposure["unknown"])
    recognised = [c for c in i.controls if c in cfg.controls]
    controls_factor = math.prod(cfg.controls[c] for c in recognised)
    unrecognised = [c for c in i.controls if c not in cfg.controls]
    if unrecognised:
        dq.append(f"controls not in the model were ignored: {sorted(unrecognised)}")

    attackability = exposure * exploitability * controls_factor
    threat = math.sqrt(max(0.0, likelihood * attackability))
    business = cfg.criticality_factor(i.asset_criticality)
    impact = cfg.severity_weight * sev + (1 - cfg.severity_weight) * business
    relevance = cfg.path_relevance.get(i.path_relevance, cfg.path_relevance["not_on_path"])
    score = round(min(10.0, max(0.0, 10 * impact * threat * relevance)), 2)

    components = {
        "model": {"name": cfg.name, "version": cfg.version, "config_hash": cfg.config_hash(), "formula": FORMULA},
        "severity": {"value": round(sev, 3), "cvss_score": i.cvss_score, "source": i.cvss_source},
        "likelihood": {
            "value": round(likelihood, 3),
            "basis": basis,
            "epss": i.epss,
            "in_kev": i.in_kev,
            "assumed": basis == "assumed_missing",
        },  # fmt: skip
        "exploitability": {
            "value": round(exploitability, 3),
            "from_cvss_vector": not ex_assumed,
            "prerequisites": cv.prerequisites() if cv else [],
            "assumed": ex_assumed,
        },  # fmt: skip
        "exposure": {"value": exposure, "level": i.exposure_level},
        "controls": {"value": round(controls_factor, 3), "applied": recognised, "ignored": unrecognised},
        "attackability": {"value": round(attackability, 3)},
        "threat": {"value": round(threat, 4)},
        "business_impact": {"value": business, "criticality": i.asset_criticality},
        "impact": {"value": round(impact, 3), "severity_weight": cfg.severity_weight},
        "path_relevance": {"value": relevance, "position": i.path_relevance},
        "data_quality": dq,
    }
    return RiskResult(score, cfg.band(score), round(threat, 4), components, dq)
