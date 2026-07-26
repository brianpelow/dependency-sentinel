"""Risk engine tests: the security floor and independent staleness."""

from __future__ import annotations

from sentinel.models import (
    Advisory,
    Dependency,
    DependencyAssessment,
    Ecosystem,
    RegistryFacts,
    RiskLevel,
    Severity,
)
from sentinel.risk import assess_risk


def dep():
    return Dependency("pkg", Ecosystem.PYPI, "==1.0.0", "1.0.0")


def assess(facts=None, advisories=None):
    a = DependencyAssessment(
        dependency=dep(),
        facts=facts or RegistryFacts(current_version="1.0.0", versions_behind=0),
        advisories=advisories or [],
    )
    return assess_risk(a)


def test_clean_and_current_is_none():
    assert assess().risk is RiskLevel.NONE


def test_critical_advisory_forces_critical():
    a = assess(advisories=[Advisory("CVE-1", Severity.CRITICAL, "x", ">=1")])
    assert a.risk is RiskLevel.CRITICAL


def test_high_advisory_forces_high():
    a = assess(advisories=[Advisory("CVE-1", Severity.HIGH, "x", ">=1")])
    assert a.risk is RiskLevel.HIGH


def test_security_floor_not_lowered_by_being_current():
    """A critical advisory on a fully-current dependency stays critical."""
    a = assess(
        facts=RegistryFacts(current_version="1.0.0", versions_behind=0),
        advisories=[Advisory("CVE-1", Severity.CRITICAL, "x", ">=1")],
    )
    assert a.risk is RiskLevel.CRITICAL


def test_staleness_alone_raises_risk():
    a = assess(facts=RegistryFacts(current_version="5.0", versions_behind=25))
    assert a.risk is RiskLevel.HIGH


def test_moderate_staleness_is_medium():
    a = assess(facts=RegistryFacts(current_version="2.0", versions_behind=10))
    assert a.risk is RiskLevel.MEDIUM


def test_yanked_version_is_high():
    a = assess(facts=RegistryFacts(current_version="1.1", versions_behind=1, is_yanked=True))
    assert a.risk is RiskLevel.HIGH


def test_registry_unavailable_is_low_not_none():
    """An unreachable registry must never read as 'no risk'."""
    a = assess(facts=RegistryFacts(fetch_ok=False))
    assert a.risk is RiskLevel.LOW
    assert "unavailable" in a.risk_reasons[0].lower()


def test_unknown_severity_advisory_not_dismissed():
    a = assess(advisories=[Advisory("X", Severity.UNKNOWN, "x", ">=1")])
    assert a.risk is RiskLevel.MEDIUM


def test_reasons_are_populated():
    a = assess(advisories=[Advisory("CVE-1", Severity.HIGH, "x", ">=1")])
    assert a.risk_reasons
    assert "CVE-1" in a.risk_reasons[0]


def test_max_severity_property():
    a = DependencyAssessment(
        dependency=dep(),
        advisories=[
            Advisory("A", Severity.LOW, "x", ">=1"),
            Advisory("B", Severity.CRITICAL, "x", ">=1"),
        ],
    )
    assert a.max_severity is Severity.CRITICAL