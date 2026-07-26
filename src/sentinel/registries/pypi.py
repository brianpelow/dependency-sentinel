"""PyPI registry client."""

from __future__ import annotations

import httpx

from packaging import version as pkgversion

from sentinel.models import Dependency, RegistryFacts

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
TIMEOUT = 20.0


def _get_json(url: str, http: object | None):
    if http is not None:
        return http.get(url)
    with httpx.Client(timeout=TIMEOUT) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _sorted_releases(releases: dict) -> list[str]:
    """Release version strings sorted ascending by PEP 440, invalid ones dropped."""
    valid = []
    for v in releases:
        try:
            valid.append((pkgversion.parse(v), v))
        except Exception:
            continue
    valid.sort(key=lambda t: t[0])
    return [v for _, v in valid]


def _release_date(releases: dict, ver: str) -> str:
    files = releases.get(ver) or []
    for f in files:
        ts = f.get("upload_time_iso_8601") or f.get("upload_time")
        if ts:
            return ts[:10]
    return ""


def fetch(dep: Dependency, http: object | None = None) -> RegistryFacts:
    try:
        data = _get_json(PYPI_JSON.format(name=dep.name), http)
    except Exception as exc:
        return RegistryFacts(fetch_ok=False, fetch_note=f"PyPI fetch failed: {str(exc)[:60]}")

    info = data.get("info", {})
    releases = data.get("releases", {})
    current = info.get("version", "")

    ordered = _sorted_releases(releases)
    facts = RegistryFacts(
        current_version=current,
        current_released=_release_date(releases, current),
    )

    if dep.pinned_version and dep.pinned_version in releases:
        facts.installed_released = _release_date(releases, dep.pinned_version)
        try:
            idx_installed = ordered.index(dep.pinned_version)
            idx_current = ordered.index(current) if current in ordered else len(ordered) - 1
            facts.versions_behind = max(0, idx_current - idx_installed)
        except ValueError:
            facts.versions_behind = 0
        # yanked detection: all files for the pinned version yanked
        files = releases.get(dep.pinned_version) or []
        facts.is_yanked = bool(files) and all(f.get("yanked", False) for f in files)

    return facts