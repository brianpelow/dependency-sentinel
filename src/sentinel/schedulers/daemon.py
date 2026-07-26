"""Local daemon scheduler.

A long-lived process that runs a triage pass on a cron-like schedule using
APScheduler. This is scheduler shell B: for teams that want an always-on
service rather than CI cron. It is a thin wrapper -- it builds the same config
the CLI does and calls the same engine.

APScheduler is an optional dependency (the `daemon` extra), so this module
imports it lazily and gives a clear message if it is missing.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.discover import GitHubClient, from_github, from_local
from sentinel.emit import to_json, to_markdown
from sentinel.engine import EngineConfig, run_with_delta
from sentinel.llm import LLMClient
from sentinel.models import RiskLevel
from sentinel.state import StateStore


def _one_pass(owner: str | None, local: str | None, offline: bool,
              state_path: str, out_dir: str) -> None:
    if owner:
        manifests = from_github(owner, GitHubClient(token=os.environ.get("GITHUB_TOKEN", "")))
        target = f"github:{owner}"
    else:
        manifests = from_local(local)
        target = f"local:{local}"

    llm = None if offline else LLMClient()
    config = EngineConfig(scan_target=target, offline=offline,
                          narrate_from_risk=RiskLevel.HIGH, llm=llm)
    store = StateStore(Path(state_path))
    report, delta = run_with_delta(manifests, config, store)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sentinel.report.json").write_text(to_json(report, delta), encoding="utf-8")
    (out / "sentinel.report.md").write_text(to_markdown(report, delta), encoding="utf-8")

    crit = report.by_risk.get("critical", 0)
    print(f"[sentinel] pass complete for {target}: "
          f"{len(report.assessments)} deps, {crit} critical, "
          f"{'changes' if delta.has_changes else 'no changes'}")


def run_daemon(
    owner: str | None = None,
    local: str | None = None,
    cron: str = "0 6 * * *",
    offline: bool = False,
    state_path: str = "state/sentinel.state.json",
    out_dir: str = "out",
) -> None:
    """Start the scheduler. Blocks until interrupted.

    cron is a standard 5-field cron expression; the default is daily at 06:00.
    """
    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError as exc:
        raise SystemExit(
            "The daemon scheduler needs APScheduler. Install with: "
            "uv pip install 'dependency-sentinel[daemon]'"
        ) from exc

    scheduler = BlockingScheduler()
    scheduler.add_job(
        _one_pass,
        CronTrigger.from_crontab(cron),
        args=[owner, local, offline, state_path, out_dir],
        id="triage",
        replace_existing=True,
    )
    print(f"[sentinel] daemon started; schedule '{cron}'. Running one pass now, then on schedule.")
    _one_pass(owner, local, offline, state_path, out_dir)  # immediate first pass
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("[sentinel] daemon stopped.")