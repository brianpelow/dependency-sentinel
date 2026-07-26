# Changelog

## [0.1.0] - 2026-07-26

### Added
- Transport-agnostic triage engine: parse, enrich, assess, score
- Python (requirements.txt, pyproject.toml) and Node (package.json) parsers
- PyPI and npm registry clients for version currency
- OSV.dev client for deterministic vulnerability advisories
- Deterministic risk engine with a security floor and independent staleness signal
- Optional LLM migration narrative with fallback chain and graceful degradation
- Delta state store: reports what changed since the last run
- JSON event payload and markdown report emitters
- GitHub org/user and local directory manifest discovery
- Two schedulers: GitHub Actions cron and APScheduler daemon
- Config/posture layer with auditable egress surface
- 51 tests, all offline
