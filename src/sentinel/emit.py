"""Emitters: the JSON event payload and the human markdown report.

The JSON is the enterprise async-event payload -- a complete, structured
description of the run plus the delta, suitable for a downstream consumer
(a queue, a webhook, a SIEM). The markdown is for a human skimming what changed.

Both lead with the delta, because in a scheduled context the change since last
run is the point. A run with no changes produces a short, honest "nothing new"
rather than a wall of unchanged dependencies.
"""

from __future__ import annotations

import json

from sentinel.models import RiskLevel, TriageReport
from sentinel.state import Delta


def to_json(report: TriageReport, delta: Delta) -> str:
    payload = report.to_dict()
    payload["delta"] = delta.to_dict()
    return json.dumps(payload, indent=2)


def _risk_emoji_free_marker(level: str) -> str:
    return {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "none": "[ok]",
    }.get(level, "[?]")


def to_markdown(report: TriageReport, delta: Delta) -> str:
    lines: list[str] = [
        "# Dependency Sentinel Report",
        "",
        f"**Generated:** {report.generated_at}  ",
        f"**Scan target:** {report.scan_target}  ",
        f"**Narrative model:** {report.llm_used or '(none)'}"
        + ("  (offline mode)" if report.offline else ""),
        "",
    ]

    # --- Delta first ------------------------------------------------------
    lines.append("## What changed since last run")
    lines.append("")
    if delta.is_first_run:
        lines.append("First run. No previous state to compare against; everything below is baseline.")
        lines.append("")
    elif not delta.has_changes:
        lines.append("No changes since the previous run. No new advisories, no risk changes.")
        lines.append("")
    else:
        if delta.new_advisories:
            lines.append(f"**{len(delta.new_advisories)} new advisory(ies):**")
            for item in delta.new_advisories:
                lines.append(f"- {item['dependency']}: {item['advisory_id']}")
            lines.append("")
        if delta.risk_increased:
            lines.append(f"**{len(delta.risk_increased)} risk increase(s):**")
            for item in delta.risk_increased:
                lines.append(f"- {item['dependency']}: {item['from']} -> {item['to']}")
            lines.append("")
        if delta.risk_decreased:
            lines.append(f"**{len(delta.risk_decreased)} risk decrease(s):**")
            for item in delta.risk_decreased:
                lines.append(f"- {item['dependency']}: {item['from']} -> {item['to']}")
            lines.append("")
        if delta.new_dependencies:
            lines.append(f"**{len(delta.new_dependencies)} new dependency(ies):** "
                         + ", ".join(delta.new_dependencies))
            lines.append("")
        if delta.removed_dependencies:
            lines.append(f"**{len(delta.removed_dependencies)} removed:** "
                         + ", ".join(delta.removed_dependencies))
            lines.append("")

    # --- Summary ----------------------------------------------------------
    counts = report.by_risk
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total dependencies: {len(report.assessments)}")
    for level in ("critical", "high", "medium", "low", "none"):
        if counts.get(level):
            lines.append(f"- {level.capitalize()}: {counts[level]}")
    if report.errors:
        lines.append(f"- Errors during run: {len(report.errors)}")
    lines.append("")

    # --- Priority items ---------------------------------------------------
    priority = report.critical_and_high
    if priority:
        lines.append("## Priority: critical and high risk")
        lines.append("")
        for a in priority:
            marker = _risk_emoji_free_marker(a.risk.value)
            lines.append(f"### {marker} {a.dependency.name} ({a.dependency.ecosystem.value})")
            lines.append("")
            lines.append(f"- Installed: `{a.dependency.pinned_version or 'unpinned'}`  "
                         f"Current: `{a.facts.current_version or 'unknown'}`")
            if a.facts.versions_behind:
                lines.append(f"- {a.facts.versions_behind} releases behind")
            for adv in a.advisories:
                fixed = f", fixed in {adv.fixed_version}" if adv.fixed_version else ""
                lines.append(f"- {adv.advisory_id} [{adv.severity.value}]: {adv.summary}{fixed}")
            lines.append(f"- Risk reasons: {'; '.join(a.risk_reasons)}")
            if a.narrative:
                lines.append("")
                lines.append(f"> {a.narrative}")
            lines.append("")

    # --- Errors -----------------------------------------------------------
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for e in report.errors:
            lines.append(f"- {e}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Security advisories are sourced deterministically from OSV.dev. "
                 "Narrative notes, where present, are model-generated and never alter a "
                 "risk finding.*")
    lines.append("")

    return "\n".join(lines)