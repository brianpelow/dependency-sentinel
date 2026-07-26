"""Python manifest parsers: requirements.txt and pyproject.toml.

These extract declared dependencies and, where a spec pins an exact version,
the pinned version. Parsing is deliberately conservative: a line we cannot
confidently interpret is skipped rather than guessed, because a wrong parse
feeds a wrong risk assessment downstream.
"""

from __future__ import annotations

import re

from sentinel.models import Dependency, Ecosystem

# name, optional extras, then the spec. Handles: pkg==1.2.3, pkg>=1,<2, pkg~=1.4
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~].*)?\s*$"
)
_PIN = re.compile(r"==\s*([A-Za-z0-9._+-]+)")


def _clean(line: str) -> str:
    # Strip inline comments and whitespace; drop env markers after ';'.
    line = line.split("#", 1)[0]
    line = line.split(";", 1)[0]
    return line.strip()


def parse_requirements(text: str, manifest_path: str = "requirements.txt") -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = _clean(raw)
        if not line or line.startswith("-"):
            # Skip blanks and pip directives (-r, -e, --hash, etc.)
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group(1)
        spec = (m.group(3) or "").strip()
        pin = _PIN.search(spec)
        deps.append(
            Dependency(
                name=name,
                ecosystem=Ecosystem.PYPI,
                declared_spec=spec or "(unpinned)",
                pinned_version=pin.group(1) if pin else "",
                is_direct=True,
                manifest_path=manifest_path,
            )
        )
    return deps


def parse_pyproject(text: str, manifest_path: str = "pyproject.toml") -> list[Dependency]:
    """Parse PEP 621 [project].dependencies and optional-dependencies.

    Uses tomllib from the stdlib. Poetry's [tool.poetry.dependencies] is a
    different shape; a Poetry parser can be added later as its own path.
    """
    import tomllib

    try:
        data = tomllib.loads(text)
    except Exception:
        return []

    deps: list[Dependency] = []
    project = data.get("project", {})

    def add(spec_str: str) -> None:
        parsed = parse_requirements(spec_str, manifest_path)
        deps.extend(parsed)

    for entry in project.get("dependencies", []):
        add(entry)

    for group in project.get("optional-dependencies", {}).values():
        for entry in group:
            add(entry)

    return deps