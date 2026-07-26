# dependency-sentinel

> A scheduled, async dependency-triage agent for the enterprise. It discovers manifests across an org, scores each dependency for security and staleness risk, and reports what changed since the last run. Security findings come deterministically from OSV.dev; the risk never depends on a language model.

![CI](https://github.com/brianpelow/dependency-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)

## What it does

Point it at a GitHub org (or a local tree). It finds every `requirements.txt`, `pyproject.toml`, and `package.json`, and for each declared dependency it establishes:

- **Currency** -- current version, how many releases behind, from PyPI and npm.
- **Security** -- known advisories affecting the pinned version, from OSV.dev.
- **Risk** -- a deterministic level (critical / high / medium / low / none) with named reasons.

Then, for high-risk items only, an optional LLM writes a short migration note. The security finding is never model-generated -- the model cannot invent an advisory, and it cannot suppress one.

It is built to run on a schedule and report the **delta**: "3 new advisories and 2 risk increases since yesterday," not a nightly re-dump of the whole tree.

## Why it is built this way

**Security is deterministic.** Advisories come only from OSV.dev. The risk engine imposes a security floor a known critical advisory sets risk to critical, and being otherwise up to date cannot lower it. A vulnerability is not something a probabilistic model should be able to talk you out of.

**It degrades on every axis.** No LLM key means no narrative but a complete risk report. Offline mode skips all network and runs on local manifests. A registry timeout marks one dependency's currency unknown and the run continues. OSV being unreachable records a security-data gap rather than a false all-clear.

**The engine is transport-agnostic.** It knows nothing about scheduling. Two thin shells drive it: a GitHub Actions cron and an APScheduler daemon. That is what makes it a real async event source rather than a script.

**The network posture is auditable.** `sentinel posture` prints the exact egress surface and which secrets are present, without exposing any value.

## Run it

```bash
uv sync

# Scan a GitHub org (needs GITHUB_TOKEN for the rate limit)
uv run sentinel run --github my-org

# Scan a local tree, fully offline
uv run sentinel run --local . --offline

# See exactly what it would contact and which secrets are set
uv run sentinel posture
```

Add a migration narrative by setting a free OpenRouter key:

```bash
export OPENROUTER_API_KEY=sk-or-...
uv run sentinel run --github my-org
```

Outputs land in `out/` as `sentinel.report.json` (the async-event payload) and `sentinel.report.md` (human report). Delta state persists in `state/`.

## Scheduling

**GitHub Actions** (`.github/workflows/triage.yml`) -- runs daily at 06:00 UTC, commits the report and state so the delta persists across runs. Set `OPENROUTER_API_KEY` as a repo secret to enable narratives.

**Local daemon** -- for an always-on service:

```bash
uv pip install "dependency-sentinel[daemon]"
python -c "from sentinel.schedulers.daemon import run_daemon; run_daemon(owner='my-org', cron='0 6 * * *')"
```

## Network egress

The complete outbound surface, all disableable:

| Endpoint | Purpose | Disabled by |
|----------|---------|-------------|
| pypi.org | Python version facts | `--offline` |
| registry.npmjs.org | Node version facts | `--offline` |
| api.osv.dev | Vulnerability advisories | `--offline` |
| api.github.com | Repo/manifest discovery | `--offline` or `--local` |
| openrouter.ai | Migration narrative | `--offline`, `--no-llm`, or no key |

## Extending

A new ecosystem is a parser module plus a registry client plus an OSV ecosystem-name mapping -- registered in one dict each. The engine, risk model, delta, and emitters do not change. Python and Node ship today.

## Design decisions

- [0001](./docs/adr/0001-transport-agnostic-engine.md) -- The engine is transport-agnostic; scheduling is an outer shell
- [0002](./docs/adr/0002-deterministic-security-path.md) -- Security findings come only from OSV, never from the LLM

## License

Apache 2.0
