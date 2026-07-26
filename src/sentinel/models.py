"""Core domain models. The contract every layer depends on.

Design note: the security-relevant fields (advisories) are populated only by the
deterministic OSV.dev path, never by the LLM. The narrative field is the only
place LLM output lands, and nothing downstream reads it to make a decision.
That separation is enforced structurally by keeping the fields distinct here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"


class Severity(str, Enum):
    """Advisory severity, taken from OSV.dev, ordered for comparison."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        order = {
            "critical": 4,
            "high": 3,
            "moderate": 2,
            "low": 1,
            "unknown": 0,
        }
        return order[self.value]


class RiskLevel(str, Enum):
    """The deterministic overall risk classification for a dependency."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass(frozen=True)
class Dependency:
    """A single declared dependency, as parsed from a manifest."""

    name: str
    ecosystem: Ecosystem
    declared_spec: str  # the raw version spec, e.g. ">=1.2,<2" or "^3.1.0"
    pinned_version: str = ""  # resolved exact version if the spec pins one
    is_direct: bool = True
    manifest_path: str = ""

    def key(self) -> str:
        return f"{self.ecosystem.value}:{self.name}"


@dataclass(frozen=True)
class Advisory:
    """A known vulnerability. Populated ONLY from OSV.dev, never from an LLM."""

    advisory_id: str  # e.g. GHSA-xxxx or CVE-xxxx
    severity: Severity
    summary: str
    affected_range: str
    fixed_version: str = ""

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "severity": self.severity.value,
            "summary": self.summary,
            "affected_range": self.affected_range,
            "fixed_version": self.fixed_version,
        }


@dataclass
class RegistryFacts:
    """Deterministic facts about a dependency from its registry."""

    current_version: str = ""
    current_released: str = ""  # ISO date of the latest release
    installed_released: str = ""  # ISO date of the pinned/installed version
    versions_behind: int = 0
    is_yanked: bool = False
    fetch_ok: bool = True  # False if the registry could not be reached
    fetch_note: str = ""


@dataclass
class DependencyAssessment:
    """The full triage result for one dependency.

    Deterministic fields (facts, advisories, risk) are computed from rules and
    data. The narrative field is optional LLM prose and is never read to make a
    decision.
    """

    dependency: Dependency
    facts: RegistryFacts = field(default_factory=RegistryFacts)
    advisories: list[Advisory] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.NONE
    risk_reasons: list[str] = field(default_factory=list)
    narrative: str = ""  # optional LLM migration note; never load-bearing

    @property
    def max_severity(self) -> Severity:
        if not self.advisories:
            return Severity.UNKNOWN
        return max((a.severity for a in self.advisories), key=lambda s: s.rank)

    def to_dict(self) -> dict:
        return {
            "name": self.dependency.name,
            "ecosystem": self.dependency.ecosystem.value,
            "declared_spec": self.dependency.declared_spec,
            "pinned_version": self.dependency.pinned_version,
            "is_direct": self.dependency.is_direct,
            "manifest_path": self.dependency.manifest_path,
            "current_version": self.facts.current_version,
            "versions_behind": self.facts.versions_behind,
            "is_yanked": self.facts.is_yanked,
            "registry_ok": self.facts.fetch_ok,
            "advisories": [a.to_dict() for a in self.advisories],
            "risk": self.risk.value,
            "risk_reasons": self.risk_reasons,
            "has_narrative": bool(self.narrative),
            "narrative": self.narrative,
        }


@dataclass
class TriageReport:
    """The output of one full triage run over a set of manifests."""

    generated_at: str
    scan_target: str
    assessments: list[DependencyAssessment] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    llm_used: str = ""
    offline: bool = False

    @property
    def by_risk(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.assessments:
            counts[a.risk.value] = counts.get(a.risk.value, 0) + 1
        return counts

    @property
    def critical_and_high(self) -> list[DependencyAssessment]:
        return sorted(
            (a for a in self.assessments if a.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)),
            key=lambda a: (a.risk is not RiskLevel.CRITICAL, a.dependency.name),
        )

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "scan_target": self.scan_target,
            "offline": self.offline,
            "llm_used": self.llm_used or "(none)",
            "summary": {
                "total_dependencies": len(self.assessments),
                "by_risk": self.by_risk,
                "with_advisories": sum(1 for a in self.assessments if a.advisories),
                "errors": len(self.errors),
            },
            "assessments": [a.to_dict() for a in self.assessments],
            "errors": self.errors,
        }