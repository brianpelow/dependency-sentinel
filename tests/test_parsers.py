"""Parser tests: pinned vs ranged, directives skipped, malformed handled."""

from __future__ import annotations

from sentinel.models import Ecosystem
from sentinel.parsers import node, python


def test_requirements_pinned():
    deps = python.parse_requirements("requests==2.28.0")
    assert deps[0].name == "requests"
    assert deps[0].pinned_version == "2.28.0"


def test_requirements_ranged_not_pinned():
    deps = python.parse_requirements("flask>=2.0,<3")
    assert deps[0].pinned_version == ""


def test_requirements_skips_directives_and_comments():
    text = "requests==2.0\n# comment\n-r other.txt\n-e .\n"
    deps = python.parse_requirements(text)
    assert [d.name for d in deps] == ["requests"]


def test_requirements_unpinned_bare_name():
    deps = python.parse_requirements("numpy")
    assert deps[0].name == "numpy"
    assert deps[0].declared_spec == "(unpinned)"


def test_requirements_strips_env_markers():
    deps = python.parse_requirements('requests==2.0 ; python_version < "3.9"')
    assert deps[0].name == "requests"
    assert deps[0].pinned_version == "2.0"


def test_pyproject_reads_project_dependencies():
    toml = '[project]\nname="x"\ndependencies=["requests==2.0","flask>=1"]\n'
    deps = python.parse_pyproject(toml)
    names = {d.name for d in deps}
    assert names == {"requests", "flask"}


def test_pyproject_reads_optional_dependencies():
    toml = ('[project]\nname="x"\ndependencies=[]\n'
            '[project.optional-dependencies]\ndev=["pytest==8.0"]\n')
    deps = python.parse_pyproject(toml)
    assert any(d.name == "pytest" for d in deps)


def test_pyproject_malformed_returns_empty():
    assert python.parse_pyproject("not valid toml [[[") == []


def test_package_json_dependencies_and_dev():
    pkg = '{"dependencies":{"react":"^18.0.0"},"devDependencies":{"jest":"29.0.0"}}'
    deps = node.parse_package_json(pkg)
    names = {d.name for d in deps}
    assert names == {"react", "jest"}


def test_package_json_exact_is_pinned():
    deps = node.parse_package_json('{"dependencies":{"lodash":"4.17.21"}}')
    assert deps[0].pinned_version == "4.17.21"


def test_package_json_caret_not_pinned():
    deps = node.parse_package_json('{"dependencies":{"react":"^18.0.0"}}')
    assert deps[0].pinned_version == ""


def test_package_json_malformed_returns_empty():
    assert node.parse_package_json("{not json") == []


def test_ecosystem_assignment():
    assert python.parse_requirements("x==1")[0].ecosystem is Ecosystem.PYPI
    assert node.parse_package_json('{"dependencies":{"x":"1.0.0"}}')[0].ecosystem is Ecosystem.NPM