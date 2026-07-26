# Security Policy

## Reporting

Open a [security advisory](https://github.com/brianpelow/dependency-sentinel/security/advisories/new) rather than a public issue.

## Secrets

Two secrets are read from the environment only, never written to disk, logged, or committed:

- `GITHUB_TOKEN` -- lifts the GitHub API rate limit for discovery.
- `OPENROUTER_API_KEY` -- enables the optional migration narrative.

`sentinel posture` reports whether each is present as a boolean, never its value.

## Network egress

The complete outbound surface is pypi.org, registry.npmjs.org, api.osv.dev, api.github.com, and openrouter.ai. Every one is disableable: `--offline` disables all of them; `--no-llm` or an absent key disables openrouter; `--local` removes the GitHub dependency. Run `sentinel posture` to see the active surface for a given configuration.

## Security-finding integrity

Vulnerability advisories are sourced only from OSV.dev and processed deterministically. No language model participates in deciding whether a dependency is vulnerable. See ADR 0002.
