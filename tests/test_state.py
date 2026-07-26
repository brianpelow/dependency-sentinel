"""Delta/state tests: the change detection that makes this an event source."""

from __future__ import annotations

from sentinel.models import (
    Advisory,
    Dependency,
    DependencyAssessment,
    Ecosystem,
    RegistryFacts,
    RiskLevel,
    Severity,
    TriageReport,
)
from sentinel.state import compute_delta


def _report(assessments):
    return TriageReport(generated_at="t", scan_target="test", assessments=assessments)


def _assessment(name, risk=RiskLevel.NONE, advisories=None):
    a = DependencyAssessment(
        dependency=Dependency(name, Ecosystem.PYPI, "==1.0", "1.0"),
        facts=RegistryFacts(current_version="1.0"),
        advisories=advisories or [],
    )
    a.risk = risk
    return a


def test_first_run_flagged():
    report = _report([_assessment("a")])
    delta = compute_delta(None, report)
    assert delta.is_first_run
    assert not delta.has_changes


def test_new_advisory_detected():
    prev = {"pypi:a": {"risk": "none", "advisories": [], "name": "a", "ecosystem": "pypi"}}
    report = _report([_assessment("a", RiskLevel.HIGH,
                                  [Advisory("CVE-1", Severity.HIGH, "x", ">=1")])])
    delta = compute_delta(prev, report)
    assert len(delta.new_advisories) == 1
    assert delta.new_advisories[0]["advisory_id"] == "CVE-1"


def test_risk_increase_detected():
    prev = {"pypi:a": {"risk": "low", "advisories": [], "name": "a", "ecosystem": "pypi"}}
    report = _report([_assessment("a", RiskLevel.CRITICAL)])
    delta = compute_delta(prev, report)
    assert delta.risk_increased[0]["from"] == "low"
    assert delta.risk_increased[0]["to"] == "critical"


def test_risk_decrease_detected():
    prev = {"pypi:a": {"risk": "high", "advisories": [], "name": "a", "ecosystem": "pypi"}}
    report = _report([_assessment("a", RiskLevel.LOW)])
    delta = compute_delta(prev, report)
    assert delta.risk_decreased[0]["to"] == "low"


def test_new_and_removed_dependencies():
    prev = {"pypi:old": {"risk": "none", "advisories": [], "name": "old", "ecosystem": "pypi"}}
    report = _report([_assessment("new")])
    delta = compute_delta(prev, report)
    assert "pypi:new" in delta.new_dependencies
    assert "pypi:old" in delta.removed_dependencies


def test_no_changes_when_identical():
    prev = {"pypi:a": {"risk": "none", "advisories": [], "name": "a", "ecosystem": "pypi"}}
    report = _report([_assessment("a", RiskLevel.NONE)])
    delta = compute_delta(prev, report)
    assert not delta.has_changes