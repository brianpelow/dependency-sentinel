"""Registry clients: deterministic version and release-date facts.

Each client fetches, for a dependency, the current version, its release date,
the release date of the installed version, and how many releases behind the
installed version is. All of this is fact, not judgment -- no LLM involved.

Every client accepts an injectable HTTP transport so the test suite runs with
no network. A registry that cannot be reached does not fail the run: the
dependency's facts are marked fetch_ok=False and triage continues, treating
version currency as unknown for that dependency.
"""

from __future__ import annotations

from sentinel.models import Dependency, Ecosystem, RegistryFacts
from sentinel.registries import npm, pypi


def fetch_facts(dep: Dependency, http: object | None = None) -> RegistryFacts:
    """Dispatch to the right registry client for a dependency."""
    if dep.ecosystem is Ecosystem.PYPI:
        return pypi.fetch(dep, http)
    if dep.ecosystem is Ecosystem.NPM:
        return npm.fetch(dep, http)
    return RegistryFacts(fetch_ok=False, fetch_note=f"No registry for {dep.ecosystem}")