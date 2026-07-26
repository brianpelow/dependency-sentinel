"""The deterministic risk engine.

Given a dependency's registry facts and OSV advisories, this assigns an overall
risk level with explicit, named reasons. It is pure: the same inputs always
produce the same risk and the same reasons.

Two rules govern the design:

1. Security dominates. A known critical or high advisory sets the risk floor at
   critical or high respectively, and nothing -- not being up to date, not being
   a dev dependency -- can lower it. This mirrors the floor-rule principle: a
   real vulnerability cannot be averaged away by good news elsewhere.

2. Staleness is a distinct, additive signal. Being many versions behind or on a
   yanked release raises risk even with no known vulnerability, because it is a
   leading indicator and an upgrade-debt cost.

The LLM never participates here. It later writes prose about a risk this engine
has already decided; it cannot change the decision.
"""

from __future__ import annotations

from sentinel.models import (
    Advisory,
    DependencyAssessment,
    RegistryFacts,
    RiskLevel,
    Severity,
)

# Thresholds for staleness risk from version lag.
_BEHIND_HIGH = 20
_BEHIND_MEDIUM = 8
_BEHIND_LOW = 3


def _security_floor(advisories: list[Advisory]) -> tuple[RiskLevel, list[str]]:
    """The risk floor imposed by known vulnerabilities. Never lowered elsewhere."""
    if not advisories:
        return RiskLevel.NONE, []

    max_sev = max((a.severity for a in advisories), key=lambda s: s.rank)
    ids = ", ".join(a.advisory_id for a in advisories[:3])
    more = "" if len(advisories) <= 3 else f" (+{len(advisories) - 3} more)"
    reason = f"{len(advisories)} known advisory(ies) [{ids}{more}], max severity {max_sev.value}"

    if max_sev is Severity.CRITICAL:
        return RiskLevel.CRITICAL, [reason]
    if max_sev is Severity.HIGH:
        return RiskLevel.HIGH, [reason]
    if max_sev is Severity.MODERATE:
        return RiskLevel.MEDIUM, [reason]
    if max_sev is Severity.LOW:
        return RiskLevel.LOW, [reason]
    # Advisory of unknown severity: treat as medium, do not dismiss.
    return RiskLevel.MEDIUM, [reason + " (severity unrated; treated as medium)"]


def _staleness(facts: RegistryFacts) -> tuple[RiskLevel, list[str]]:
    """Risk contributed by version lag and yanked releases."""
    reasons: list[str] = []
    level = RiskLevel.NONE

    if not facts.fetch_ok:
        return RiskLevel.LOW, ["Registry data unavailable; version currency unknown"]

    if facts.is_yanked:
        reasons.append("Installed version is yanked from the registry")
        level = RiskLevel.HIGH

    behind = facts.versions_behind
    if behind >= _BEHIND_HIGH:
        reasons.append(f"{behind} releases behind current")
        level = _max_level(level, RiskLevel.HIGH)
    elif behind >= _BEHIND_MEDIUM:
        reasons.append(f"{behind} releases behind current")
        level = _max_level(level, RiskLevel.MEDIUM)
    elif behind >= _BEHIND_LOW:
        reasons.append(f"{behind} releases behind current")
        level = _max_level(level, RiskLevel.LOW)

    return level, reasons


_ORDER = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _max_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _ORDER[a] >= _ORDER[b] else b


def assess_risk(assessment: DependencyAssessment) -> DependencyAssessment:
    """Compute and attach the risk level and reasons. Mutates and returns."""
    sec_level, sec_reasons = _security_floor(assessment.advisories)
    stale_level, stale_reasons = _staleness(assessment.facts)

    # The overall risk is the higher of the two, but the security floor can
    # never be lowered by staleness being benign.
    overall = _max_level(sec_level, stale_level)

    reasons = sec_reasons + stale_reasons
    if not reasons:
        reasons = ["Up to date, no known advisories"]

    assessment.risk = overall
    assessment.risk_reasons = reasons
    return assessment