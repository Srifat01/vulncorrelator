"""CVSS v3.x vector parsing. Gives us the *prerequisites* of an exploit (attack vector, privileges, interaction)
and the standard exploitability sub-score, instead of guessing from titles."""

from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_MAX_EXPLOITABILITY = 8.22 * 0.85 * 0.77 * 0.85 * 0.85  # 3.887: AV:N/AC:L/PR:N/UI:N

AV_NAMES = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
PR_NAMES = {"N": "none", "L": "low", "H": "high"}


@dataclass(frozen=True)
class Cvss3:
    version: str
    attack_vector: str  # network | adjacent | local | physical
    complexity: str  # low | high
    privileges_required: str  # none | low | high
    user_interaction: str  # none | required
    scope_changed: bool
    exploitability: float  # 0..1, CVSS v3 exploitability sub-score / its maximum

    def prerequisites(self) -> list[str]:
        out = []
        if self.attack_vector != "network":
            out.append(f"{self.attack_vector} access to the target (attack vector: {self.attack_vector})")
        if self.privileges_required != "none":
            out.append(f"{self.privileges_required} privileges on the target")
        if self.user_interaction == "required":
            out.append("interaction from a legitimate user")
        if self.complexity == "high":
            out.append("conditions outside the attacker's control (high attack complexity)")
        return out


def parse_cvss3(vector: str | None) -> Cvss3 | None:
    """Return None for anything that is not a well-formed CVSS:3.0/3.1 base vector (v2 and v4 are not parsed)."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        av, ac, pr, ui, scope = metrics["AV"], metrics["AC"], metrics["PR"], metrics["UI"], metrics["S"]
        changed = scope == "C"
        if scope not in ("U", "C"):
            return None
        score = 8.22 * _AV[av] * _AC[ac] * (_PR_CHANGED if changed else _PR_UNCHANGED)[pr] * _UI[ui]
    except (KeyError, ValueError):
        return None
    return Cvss3(
        version=vector[5:8],
        attack_vector=AV_NAMES[av],
        complexity="low" if ac == "L" else "high",
        privileges_required=PR_NAMES[pr],
        user_interaction="none" if ui == "N" else "required",
        scope_changed=changed,
        exploitability=round(score / _MAX_EXPLOITABILITY, 4),
    )
