"""Engine integration: the full pipeline with every external call mocked."""

from __future__ import annotations

from sentinel.engine import EngineConfig, ManifestFile, run


class FakeHTTP:
    """Serves canned PyPI/OSV responses based on the URL."""

    def get(self, url, params=None):
        # PyPI-style response
        return {
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": False}],
                "2.0.0": [{"upload_time_iso_8601": "2022-01-01T00:00:00Z", "yanked": False}],
            },
        }

    def post(self, url, json=None):
        # OSV: a high advisory for the pinned version
        return {"vulns": [{
            "id": "GHSA-test",
            "summary": "test advisory",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "vulnpkg"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
        }]}


def test_offline_run_produces_complete_report():
    manifests = [ManifestFile("requirements.txt", "requests==1.0.0\nflask", "req.txt")]
    report = run(manifests, EngineConfig(scan_target="t", offline=True))
    assert len(report.assessments) == 2
    # Offline: registry unavailable, so risk floors at low, never none-with-false-confidence
    assert all(a.risk.value in ("low",) for a in report.assessments)


def test_online_run_with_mocked_http():
    manifests = [ManifestFile("requirements.txt", "vulnpkg==1.0.0", "req.txt")]
    report = run(manifests, EngineConfig(scan_target="t", http=FakeHTTP()))
    a = report.assessments[0]
    assert a.facts.current_version == "2.0.0"
    assert a.advisories
    assert a.risk.value == "high"  # from the mocked advisory


def test_deduplication_across_manifests():
    manifests = [
        ManifestFile("requirements.txt", "requests==1.0.0", "a/req.txt"),
        ManifestFile("requirements.txt", "requests==1.0.0", "b/req.txt"),
    ]
    report = run(manifests, EngineConfig(scan_target="t", offline=True))
    assert len(report.assessments) == 1


def test_unparseable_manifest_records_error():
    manifests = [ManifestFile("unknown.lock", "whatever", "unknown.lock")]
    report = run(manifests, EngineConfig(scan_target="t", offline=True))
    assert report.errors
    assert len(report.assessments) == 0


def test_report_serializes_to_dict():
    manifests = [ManifestFile("requirements.txt", "requests==1.0.0", "req.txt")]
    report = run(manifests, EngineConfig(scan_target="t", offline=True))
    d = report.to_dict()
    assert "summary" in d
    assert "assessments" in d
    assert d["offline"] is True