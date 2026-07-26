"""The triage engine: the transport-agnostic core.

This is what a scheduler calls. It takes a set of manifests (already read into
memory as name+content pairs), runs the full pipeline, and returns a
TriageReport plus a Delta. It knows nothing about GitHub, cron, or daemons --
those are outer shells that gather manifests and deliver output.

Pipeline: parse -> registry facts -> OSV advisories -> risk -> narrative.
Every external dependency (registry HTTP, OSV HTTP, LLM) is injected, so the
whole engine runs offline in tests and in air-gapped enterprise mode.

Degradation is total and per-item: a registry timeout marks one dependency's
facts unavailable and the run continues; OSV being down records a security-data
gap rather than a false all-clear; no LLM means no narrative but a complete
report.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel import osv
from sentinel.llm import LLMClient, narrate
from sentinel.models import (
    DependencyAssessment,
    RiskLevel,
    TriageReport,
)
from sentinel.parsers import parser_for
from sentinel.registries import fetch_facts
from sentinel.risk import assess_risk
from sentinel.state import Delta, StateStore, compute_delta


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass
class ManifestFile:
    """A manifest to triage: its filename (for parser selection) and content."""

    filename: str      # e.g. "requirements.txt"
    content: str
    path: str = ""     # display path, e.g. "services/api/requirements.txt"


@dataclass
class EngineConfig:
    """Runtime configuration for a triage run."""

    scan_target: str = "manifests"
    offline: bool = False           # skip all network: no registry, no OSV, no LLM
    narrate_from_risk: RiskLevel = RiskLevel.HIGH  # narrate items at or above this
    http: object | None = None      # injected transport for registry + OSV
    llm: LLMClient | None = None    # injected LLM client


_RISK_ORDER = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _parse_all(manifests: list[ManifestFile]) -> tuple[list, list[str]]:
    deps = []
    errors: list[str] = []
    for mf in manifests:
        parser = parser_for(mf.filename)
        if parser is None:
            errors.append(f"No parser for {mf.filename} ({mf.path})")
            continue
        try:
            parsed = parser(mf.content, mf.path or mf.filename)
            deps.extend(parsed)
        except Exception as exc:
            errors.append(f"Parse failed for {mf.path or mf.filename}: {str(exc)[:60]}")
    return deps, errors


def run(manifests: list[ManifestFile], config: EngineConfig) -> TriageReport:
    """Run the full triage pipeline over a set of manifests."""
    report = TriageReport(
        generated_at=_now(),
        scan_target=config.scan_target,
        offline=config.offline,
    )

    deps, parse_errors = _parse_all(manifests)
    report.errors.extend(parse_errors)

    # Deduplicate by key, keeping the first occurrence (stable).
    seen: set[str] = set()
    unique = []
    for d in deps:
        if d.key() not in seen:
            seen.add(d.key())
            unique.append(d)

    for dep in unique:
        assessment = DependencyAssessment(dependency=dep)

        if not config.offline:
            assessment.facts = fetch_facts(dep, config.http)
            try:
                assessment.advisories = osv.query(dep, config.http)
            except osv.OSVUnavailable as exc:
                report.errors.append(f"OSV unavailable for {dep.name}: {exc}")
        else:
            assessment.facts.fetch_ok = False
            assessment.facts.fetch_note = "offline mode"

        assess_risk(assessment)
        report.assessments.append(assessment)

    # Narrative pass: only for items at or above the configured risk, and only
    # if an LLM is available and we are not offline.
    if not config.offline and config.llm is not None and config.llm.available():
        threshold = _RISK_ORDER[config.narrate_from_risk]
        narrated_any = False
        for a in report.assessments:
            if _RISK_ORDER[a.risk] >= threshold:
                note = narrate(a, config.llm)
                if note:
                    a.narrative = note
                    narrated_any = True
        if narrated_any:
            # Record which model actually produced narrative by probing one more time.
            report.llm_used = _first_model_label(config.llm)

    return report


def _first_model_label(llm: LLMClient) -> str:
    # The LLMClient does not expose which model won per call; report the chain
    # head as the nominal model. Degradation is captured per-note by the client.
    chain = getattr(llm, "_chain", ())
    return chain[0] if chain else "configured-model"


def run_with_delta(
    manifests: list[ManifestFile],
    config: EngineConfig,
    store: StateStore,
) -> tuple[TriageReport, Delta]:
    """Run triage, compute the delta against saved state, and persist new state."""
    previous = store.load()
    report = run(manifests, config)
    delta = compute_delta(previous, report)
    store.save(report)
    return report, delta