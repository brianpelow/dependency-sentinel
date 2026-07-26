"""Manifest discovery: find and read manifests to triage.

Two sources, matching the enterprise use case:

- GitHub discovery: given an org or user, enumerate public repos and locate
  manifest files in each, reading their content. This is the primary scan
  target -- a scheduled run points at an org and triages everything.
- Local discovery: walk a directory tree for manifest files. This covers
  air-gapped monorepos and offline runs.

Both return a list of ManifestFile ready for the engine. GitHub calls are
injectable so tests never hit the network, and an unauthenticated caller is
rate-limited (60/hr) while a token lifts that -- the caller supplies the token.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import httpx

from sentinel.engine import ManifestFile
from sentinel.parsers import known_manifest_names

GITHUB_API = "https://api.github.com"
TIMEOUT = 30.0


# --- local discovery ------------------------------------------------------

def from_local(root: str | Path) -> list[ManifestFile]:
    """Walk a directory for known manifest files."""
    root = Path(root)
    names = set(known_manifest_names())
    manifests: list[ManifestFile] = []
    for path in root.rglob("*"):
        if path.name in names and path.is_file():
            # Skip vendored/virtual dirs that would produce noise.
            parts = set(path.parts)
            if parts & {"node_modules", ".venv", "venv", "site-packages", ".git"}:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            manifests.append(
                ManifestFile(
                    filename=path.name,
                    content=content,
                    path=str(path.relative_to(root)),
                )
            )
    return manifests


# --- GitHub discovery -----------------------------------------------------

def _headers(token: str) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


class GitHubClient:
    """Thin GitHub client for discovery. Injectable for tests."""

    def __init__(self, token: str | None = None, http: object | None = None) -> None:
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self._http = http

    def _get(self, url: str, params: dict | None = None):
        if self._http is not None:
            return self._http.get(url, params=params)
        with httpx.Client(timeout=TIMEOUT, headers=_headers(self._token)) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()

    def list_repos(self, owner: str) -> list[str]:
        """All public repo names for an org or user, paginated."""
        names: list[str] = []
        page = 1
        while True:
            data = self._get(
                f"{GITHUB_API}/users/{owner}/repos",
                params={"type": "public", "per_page": 100, "page": page},
            )
            if not data:
                break
            names.extend(item["name"] for item in data)
            if len(data) < 100:
                break
            page += 1
            if page > 20:  # safety bound
                break
        return names

    def find_manifests(self, owner: str, repo: str) -> list[ManifestFile]:
        """Locate known manifests in a repo's tree and read their content."""
        manifests: list[ManifestFile] = []
        try:
            tree = self._get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD",
                params={"recursive": "1"},
            )
        except Exception:
            return manifests

        names = set(known_manifest_names())
        for entry in tree.get("tree", []):
            if entry.get("type") != "blob":
                continue
            path = entry.get("path", "")
            filename = path.rsplit("/", 1)[-1]
            if filename not in names:
                continue
            if any(part in path for part in ("node_modules/", ".venv/", "site-packages/")):
                continue
            content = self._read_blob(owner, repo, entry.get("sha", ""))
            if content is not None:
                manifests.append(
                    ManifestFile(filename=filename, content=content, path=f"{repo}/{path}")
                )
        return manifests

    def _read_blob(self, owner: str, repo: str, sha: str) -> str | None:
        if not sha:
            return None
        try:
            blob = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/git/blobs/{sha}")
        except Exception:
            return None
        if blob.get("encoding") == "base64":
            try:
                return base64.b64decode(blob["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return blob.get("content")


def from_github(owner: str, client: GitHubClient | None = None) -> list[ManifestFile]:
    """Discover all manifests across an owner's public repos."""
    client = client or GitHubClient()
    manifests: list[ManifestFile] = []
    for repo in client.list_repos(owner):
        manifests.extend(client.find_manifests(owner, repo))
    return manifests