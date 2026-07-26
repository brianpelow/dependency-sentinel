"""OSV.dev vulnerability client. The deterministic security layer.

OSV.dev is Google's open vulnerability database, covering PyPI, npm, and many
other ecosystems with a free batch API. This module turns a dependency into a
list of Advisory objects.

This is the security-critical path, and its integrity rests on one rule: an
Advisory is produced only from OSV data. No language model participates in
deciding whether a dependency is vulnerable, in either direction. The LLM
cannot invent an advisory, and just as importantly it cannot suppress one.

If OSV cannot be reached, the run does not silently report "no vulnerabilities"
-- that would be a dangerous false negative. Instead the failure is recorded so
the report can say security data was unavailable for that dependency.
"""

from __future__ import annotations

import httpx

from sentinel.models import Advisory, Dependency, Ecosystem, Severity

OSV_QUERY = "https://api.osv.dev/v1/query"
TIMEOUT = 25.0

# OSV ecosystem names differ from ours.
_OSV_ECOSYSTEM = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
}


class OSVUnavailable(Exception):
    """Raised when OSV cannot be reached, so the caller can mark security unknown."""


def _post(url: str, payload: dict, http: object | None):
    if http is not None:
        return http.post(url, json=payload)
    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


def _severity_from(vuln: dict) -> Severity:
    """Extract severity from an OSV vuln record.

    OSV encodes severity in a few places. We check the database_specific
    severity string first (GHSA supplies CRITICAL/HIGH/MODERATE/LOW), which is
    the most reliable categorical signal.
    """
    db = vuln.get("database_specific", {})
    label = str(db.get("severity", "")).lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MODERATE,
        "medium": Severity.MODERATE,
        "low": Severity.LOW,
    }
    return mapping.get(label, Severity.UNKNOWN)


def _fixed_version(vuln: dict, ecosystem_name: str, package: str) -> str:
    """Find the first fixed version in the affected ranges, if any."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem_name or pkg.get("name") != package:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _affected_range(vuln: dict) -> str:
    """A compact human string of the affected range, for the report."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            intro = next((e["introduced"] for e in events if "introduced" in e), "0")
            fixed = next((e["fixed"] for e in events if "fixed" in e), "")
            return f">={intro}" + (f", <{fixed}" if fixed else "")
    return "see advisory"


def query(dep: Dependency, http: object | None = None) -> list[Advisory]:
    """Return advisories affecting the pinned version of a dependency.

    If the dependency has no pinned version, OSV is queried by package only,
    which returns advisories for the package regardless of version -- still
    useful signal, flagged as such by the caller.
    """
    ecosystem_name = _OSV_ECOSYSTEM.get(dep.ecosystem)
    if ecosystem_name is None:
        return []

    payload: dict = {"package": {"name": dep.name, "ecosystem": ecosystem_name}}
    if dep.pinned_version:
        payload["version"] = dep.pinned_version

    try:
        data = _post(OSV_QUERY, payload, http)
    except Exception as exc:
        raise OSVUnavailable(str(exc)[:80]) from exc

    advisories: list[Advisory] = []
    for vuln in data.get("vulns", []):
        advisories.append(
            Advisory(
                advisory_id=vuln.get("id", "UNKNOWN"),
                severity=_severity_from(vuln),
                summary=(vuln.get("summary") or vuln.get("details", ""))[:200],
                affected_range=_affected_range(vuln),
                fixed_version=_fixed_version(vuln, ecosystem_name, dep.name),
            )
        )

    # Deterministic ordering: most severe first, then by id.
    advisories.sort(key=lambda a: (-a.severity.rank, a.advisory_id))
    return advisories