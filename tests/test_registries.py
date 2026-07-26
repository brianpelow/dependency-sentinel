"""Registry client tests: version lag math and graceful failure."""

from __future__ import annotations

from sentinel.models import Dependency, Ecosystem
from sentinel.registries import npm, pypi


class FakeHTTP:
    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise = raise_exc

    def get(self, url, params=None):
        if self._raise:
            raise self._raise
        return self._response


def test_pypi_current_version_and_lag():
    resp = {
        "info": {"version": "2.0.0"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": False}],
            "1.5.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": False}],
            "2.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": False}],
        },
    }
    dep = Dependency("pkg", Ecosystem.PYPI, "==1.0.0", "1.0.0")
    facts = pypi.fetch(dep, FakeHTTP(resp))
    assert facts.current_version == "2.0.0"
    assert facts.versions_behind == 2
    assert facts.fetch_ok


def test_pypi_yanked_detection():
    resp = {
        "info": {"version": "2.0.0"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": True}],
            "2.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": False}],
        },
    }
    dep = Dependency("pkg", Ecosystem.PYPI, "==1.0.0", "1.0.0")
    facts = pypi.fetch(dep, FakeHTTP(resp))
    assert facts.is_yanked


def test_pypi_unreachable_marks_not_ok():
    dep = Dependency("pkg", Ecosystem.PYPI, "==1.0.0", "1.0.0")
    facts = pypi.fetch(dep, FakeHTTP(raise_exc=RuntimeError("down")))
    assert not facts.fetch_ok


def test_npm_current_and_lag():
    resp = {
        "dist-tags": {"latest": "3.0.0"},
        "versions": {"1.0.0": {}, "2.0.0": {}, "3.0.0": {}},
        "time": {
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2021-01-01T00:00:00Z",
            "3.0.0": "2022-01-01T00:00:00Z",
        },
    }
    dep = Dependency("pkg", Ecosystem.NPM, "1.0.0", "1.0.0")
    facts = npm.fetch(dep, FakeHTTP(resp))
    assert facts.current_version == "3.0.0"
    assert facts.versions_behind == 2


def test_npm_unreachable_marks_not_ok():
    dep = Dependency("pkg", Ecosystem.NPM, "1.0.0", "1.0.0")
    facts = npm.fetch(dep, FakeHTTP(raise_exc=RuntimeError("down")))
    assert not facts.fetch_ok