"""npm registry client."""

from __future__ import annotations

import httpx

from sentinel.models import Dependency, RegistryFacts

NPM_JSON = "https://registry.npmjs.org/{name}"
TIMEOUT = 20.0


def _get_json(url: str, http: object | None):
    if http is not None:
        return http.get(url)
    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def fetch(dep: Dependency, http: object | None = None) -> RegistryFacts:
    try:
        data = _get_json(NPM_JSON.format(name=dep.name), http)
    except Exception as exc:
        return RegistryFacts(fetch_ok=False, fetch_note=f"npm fetch failed: {str(exc)[:60]}")

    dist_tags = data.get("dist-tags", {})
    current = dist_tags.get("latest", "")
    times = data.get("time", {})  # version -> ISO timestamp
    versions = data.get("versions", {})

    facts = RegistryFacts(
        current_version=current,
        current_released=(times.get(current, "")[:10] if times.get(current) else ""),
    )

    if dep.pinned_version and dep.pinned_version in versions:
        facts.installed_released = (
            times.get(dep.pinned_version, "")[:10] if times.get(dep.pinned_version) else ""
        )
        # versions_behind: count published versions between installed and latest.
        published = [v for v in versions if v in times]
        published.sort(key=lambda v: times.get(v, ""))
        try:
            idx_installed = published.index(dep.pinned_version)
            idx_current = published.index(current) if current in published else len(published) - 1
            facts.versions_behind = max(0, idx_current - idx_installed)
        except ValueError:
            facts.versions_behind = 0

    return facts