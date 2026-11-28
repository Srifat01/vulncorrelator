"""Versioned, configurable parameters of the contextual risk model.

Everything that is a judgement call lives here (not scattered in code), is documented, is reported with every
score (`risk_model_version` + `config_hash`), and can be overridden from a JSON file (RISK_MODEL_CONFIG_PATH).
None of these numbers is empirically calibrated: they encode a transparent prioritisation policy, not a probability.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from functools import lru_cache
from pathlib import Path

from app.config import get_settings


def _exposure() -> dict[str, float]:
    return {
        "internet_observed": 1.0,  # an external scan or declared flow shows the service is reachable from the internet
        "internet_inferred": 0.8,  # asset flagged internet-facing / public IP, but this port was not verified
        "internal_flow": 0.5,  # reachable only from internal hosts that have an observed/declared flow to it
        "local_only": 0.3,  # host-level flaw with no remote service: exploitable only after a foothold
        "unknown": 0.3,  # no reachability evidence at all (neither exposed nor known to be isolated)
        "none": 0.0,
    }


def _criticality() -> dict[int, float]:
    return {1: 0.2, 2: 0.4, 3: 0.6, 4: 0.8, 5: 1.0}


def _controls() -> dict[str, float]:
    """Multiplier on attackability for a declared control. Assumed effectiveness, NOT measured."""
    return {
        "waf": 0.8,
        "edr": 0.9,
        "ids": 0.95,
        "ips": 0.9,
        "mfa": 0.85,
        "network_segmentation": 0.7,
        "application_allowlisting": 0.85,
        "virtual_patching": 0.8,
    }


def _relevance() -> dict[str, float]:
    return {"reaches_target": 1.0, "on_attack_path": 0.85, "not_on_path": 0.7}


def _bands() -> dict[str, float]:
    return {"critical": 7.5, "high": 5.0, "medium": 2.5}  # >= threshold; below medium => low


@dataclass(frozen=True)
class RiskModelConfig:
    version: str = "2.0"
    name: str = "contextual-v2"
    # impact = severity_weight * (CVSS/10) + (1 - severity_weight) * business_impact
    severity_weight: float = 0.5
    # likelihood = max(kev_floor if on CISA KEV, EPSS). KEV is *observed* exploitation, so it dominates a prediction.
    kev_likelihood_floor: float = 1.0
    # Used ONLY when no EPSS value exists for a CVE; the score is then flagged `assumed` and listed in data_quality.
    # Deliberately conservative: missing intelligence must never reassure (unknown is not the same as low).
    missing_epss_likelihood: float = 0.2
    unknown_vector_exploitability: float = 0.5  # when no CVSS v3 vector is available to derive prerequisites
    exposure: dict[str, float] = field(default_factory=_exposure)
    criticality: dict[int, float] = field(default_factory=_criticality)
    controls: dict[str, float] = field(default_factory=_controls)
    path_relevance: dict[str, float] = field(default_factory=_relevance)
    bands: dict[str, float] = field(default_factory=_bands)
    # attack-path scoring
    path_length_decay: float = 0.9  # per extra step: longer chains are harder to execute end to end
    path_nonvuln_step_factor: float = 0.6  # credential / trust steps have no CVE to score
    path_unknown_threat: float = 0.3

    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, default=str).encode()).hexdigest()[:12]

    def band(self, score: float) -> str:
        for name in ("critical", "high", "medium"):
            if score >= self.bands[name]:
                return name
        return "low"

    def criticality_factor(self, level: int) -> float:
        return self.criticality.get(max(1, min(5, int(level))), 0.6)


def _coerce(base: RiskModelConfig, overrides: dict) -> RiskModelConfig:
    known = {f.name for f in fields(RiskModelConfig)}
    bad = set(overrides) - known
    if bad:
        raise ValueError(f"unknown risk-model setting(s): {sorted(bad)}")
    merged = {**asdict(base), **overrides}
    for key in ("exposure", "criticality", "controls", "path_relevance", "bands"):
        merged[key] = {**asdict(base)[key], **overrides.get(key, {})}
    merged["criticality"] = {int(k): float(v) for k, v in merged["criticality"].items()}
    return RiskModelConfig(**merged)


@lru_cache
def load_risk_config() -> RiskModelConfig:
    path: Path | None = get_settings().risk_model_config_path
    base = RiskModelConfig()
    if path is None:
        return base
    return _coerce(base, json.loads(Path(path).read_text()))
