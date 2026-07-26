"""OSV client tests: advisory extraction and the unavailable-means-unknown rule."""

from __future__ import annotations

import pytest

from sentinel.models import Dependency, Ecosystem, Severity
from sentinel.osv import OSVUnavailable, query


class FakeHTTP:
    def __init__(self, response=None, raise_exc=None):
        self._response = response or {"vulns": []}
        self._raise = raise_exc

    def post(self, url, json=None):
        if self._raise:
            raise self._raise
        return self._response


def dep(pinned="1.0.0"):
    return Dependency("pkg", Ecosystem.PYPI, f"=={pinned}", pinned)


def test_no_vulns_returns_empty():
    assert query(dep(), FakeHTTP({"vulns": []})) == []


def test_extracts_advisory_id_and_severity():
    resp = {"vulns": [{
        "id": "GHSA-xxxx",
        "summary": "bad thing",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "pkg"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
    }]}
    advs = query(dep(), FakeHTTP(resp))
    assert advs[0].advisory_id == "GHSA-xxxx"
    assert advs[0].severity is Severity.HIGH
    assert advs[0].fixed_version == "2.0"


def test_advisories_sorted_by_severity():
    resp = {"vulns": [
        {"id": "LOW-1", "database_specific": {"severity": "LOW"}, "summary": ""},
        {"id": "CRIT-1", "database_specific": {"severity": "CRITICAL"}, "summary": ""},
    ]}
    advs = query(dep(), FakeHTTP(resp))
    assert advs[0].advisory_id == "CRIT-1"


def test_unknown_severity_maps_to_unknown():
    resp = {"vulns": [{"id": "X", "summary": "", "database_specific": {}}]}
    advs = query(dep(), FakeHTTP(resp))
    assert advs[0].severity is Severity.UNKNOWN


def test_osv_unreachable_raises_not_silent():
    """A network failure must raise, never return an empty (false all-clear) list."""
    with pytest.raises(OSVUnavailable):
        query(dep(), FakeHTTP(raise_exc=RuntimeError("timeout")))