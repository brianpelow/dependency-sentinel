"""Command-line interface: the shared entry point both schedulers call.

This is deliberately the seam between the transport-agnostic engine and the
outside world. A GitHub Actions cron invokes `sentinel run`. The local daemon
invokes the same code path on a schedule. Nothing about scheduling lives in the
engine.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sentinel.discover import GitHubClient, from_github, from_local
from sentinel.emit import to_json, to_markdown
from sentinel.engine import EngineConfig, run_with_delta
from sentinel.llm import LLMClient
from sentinel.models import RiskLevel
from sentinel.state import StateStore


def _gather(args) -> tuple[list, str]:
    """Return (manifests, scan_target_label) from the chosen source."""
    if args.github:
        token = os.environ.get("GITHUB_TOKEN", "")
        client = GitHubClient(token=token)
        return from_github(args.github, client), f"github:{args.github}"
    if args.local:
        return from_local(args.local), f"local:{args.local}"
    raise SystemExit("Specify a scan target: --github OWNER or --local PATH")


def _run(args) -> int:
    manifests, target = _gather(args)
    if not manifests:
        print(f"No manifests found for {target}", file=sys.stderr)
        return 0

    offline = args.offline
    llm = None if (offline or args.no_llm) else LLMClient()

    config = EngineConfig(
        scan_target=target,
        offline=offline,
        narrate_from_risk=RiskLevel.HIGH,
        llm=llm,
    )

    store = StateStore(Path(args.state))
    report, delta = run_with_delta(manifests, config, store)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "sentinel.report.json"
    md_path = out_dir / "sentinel.report.md"
    json_path.write_text(to_json(report, delta), encoding="utf-8")
    md_path.write_text(to_markdown(report, delta), encoding="utf-8")

    counts = report.by_risk
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    print(f"Triaged {len(report.assessments)} dependencies from {target}")
    print(f"  critical: {crit}  high: {high}")
    if delta.is_first_run:
        print("  (first run, baseline established)")
    elif delta.has_changes:
        print(f"  changes: {len(delta.new_advisories)} new advisories, "
              f"{len(delta.risk_increased)} risk increases")
    else:
        print("  no changes since last run")
    print(f"Reports written to {json_path} and {md_path}")

    # Exit non-zero if critical risk is present, so CI/cron can gate on it.
    if args.fail_on_critical and crit > 0:
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Scheduled dependency triage: registry currency + OSV advisories.",
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a triage pass.")
    src = run_p.add_mutually_exclusive_group()
    src.add_argument("--github", metavar="OWNER", help="Scan all public repos of a GitHub org/user.")
    src.add_argument("--local", metavar="PATH", help="Scan a local directory tree.")
    run_p.add_argument("--offline", action="store_true", help="No network: skip registry, OSV, LLM.")
    run_p.add_argument("--no-llm", action="store_true", help="Skip the narrative pass.")
    run_p.add_argument("--state", default="state/sentinel.state.json", help="State file path.")
    run_p.add_argument("--out-dir", default="out", help="Where to write reports.")
    run_p.add_argument("--fail-on-critical", action="store_true",
                       help="Exit non-zero if any critical-risk dependency is found.")

    args = parser.parse_args()

    if args.command == "run":
        return _run(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())