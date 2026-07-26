"""Delta state: what changed since the last run.

A scheduled agent that re-reports the same 400 dependencies every night is
noise. The signal is the change: a new advisory, a risk that rose, a dependency
that appeared or disappeared. This module persists a compact fingerprint of each
run and diffs the current run against the previous one.

The fingerprint is deliberately small -- per dependency, its risk level and the
set of advisory ids. That is enough to detect the transitions that matter
without storing the whole report. State is a single JSON file, so it commits
cleanly alongside a GitHub Actions run or lives next to a daemon.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.models import TriageReport


def _fingerprint(report: TriageReport) -> dict[str, dict]:
    """A compact per-dependency snapshot: risk level and advisory ids."""
    fp: dict[str, dict] = {}
    for a in report.assessments:
        fp[a.dependency.key()] = {
            "risk": a.risk.value,
            "advisories": sorted(adv.advisory_id for adv in a.advisories),
            "name": a.dependency.name,
            "ecosystem": a.dependency.ecosystem.value,
        }
    return fp


@dataclass
class Delta:
    """The change between two runs."""

    new_dependencies: list[str] = field(default_factory=list)
    removed_dependencies: list[str] = field(default_factory=list)
    new_advisories: list[dict] = field(default_factory=list)   # {key, advisory_id}
    risk_increased: list[dict] = field(default_factory=list)   # {key, from, to}
    risk_decreased: list[dict] = field(default_factory=list)
    is_first_run: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_dependencies
            or self.removed_dependencies
            or self.new_advisories
            or self.risk_increased
            or self.risk_decreased
        )

    def to_dict(self) -> dict:
        return {
            "is_first_run": self.is_first_run,
            "has_changes": self.has_changes,
            "new_dependencies": self.new_dependencies,
            "removed_dependencies": self.removed_dependencies,
            "new_advisories": self.new_advisories,
            "risk_increased": self.risk_increased,
            "risk_decreased": self.risk_decreased,
        }


_RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def compute_delta(previous: dict | None, report: TriageReport) -> Delta:
    """Diff the current report against a previous fingerprint."""
    current = _fingerprint(report)

    if not previous:
        return Delta(is_first_run=True)

    delta = Delta()

    prev_keys = set(previous)
    curr_keys = set(current)

    delta.new_dependencies = sorted(curr_keys - prev_keys)
    delta.removed_dependencies = sorted(prev_keys - curr_keys)

    for key in sorted(curr_keys & prev_keys):
        prev = previous[key]
        curr = current[key]

        prev_advs = set(prev.get("advisories", []))
        curr_advs = set(curr.get("advisories", []))
        for adv_id in sorted(curr_advs - prev_advs):
            delta.new_advisories.append({"dependency": key, "advisory_id": adv_id})

        prev_risk = prev.get("risk", "none")
        curr_risk = curr.get("risk", "none")
        if _RISK_ORDER.get(curr_risk, 0) > _RISK_ORDER.get(prev_risk, 0):
            delta.risk_increased.append({"dependency": key, "from": prev_risk, "to": curr_risk})
        elif _RISK_ORDER.get(curr_risk, 0) < _RISK_ORDER.get(prev_risk, 0):
            delta.risk_decreased.append({"dependency": key, "from": prev_risk, "to": curr_risk})

    return delta


class StateStore:
    """Persists run fingerprints to a JSON file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> dict | None:
        if not self._path.exists():
            return None
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def save(self, report: TriageReport) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fp = _fingerprint(report)
        self._path.write_text(json.dumps(fp, sort_keys=True, indent=2), encoding="utf-8")