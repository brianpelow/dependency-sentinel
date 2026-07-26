# Contributing

## Setup

```bash
uv sync --all-extras
uv run pytest
uv run ruff check src tests
```

## The two invariants

1. **Security stays deterministic.** Advisories come only from OSV.dev, through fixed rules. No LLM in the security path, in either direction. See ADR 0002.
2. **The engine stays transport-agnostic.** Scheduling logic lives in shells under `schedulers/`, never in the engine. See ADR 0001.

## Tests make no network calls

Every external call (registry, OSV, GitHub, LLM) is injectable and mocked in tests. A test that needs the network is a test written wrong.

## Adding an ecosystem

1. A parser in `src/sentinel/parsers/`, registered in `PARSERS`.
2. A registry client in `src/sentinel/registries/`, dispatched in `fetch_facts`.
3. An OSV ecosystem-name mapping in `osv.py`.
Nothing else changes.
