"""Node manifest parser: package.json.

Extracts dependencies and devDependencies. npm specs use range operators
(^, ~, >=) and the pinned version is only clear when the spec is exact.
"""

from __future__ import annotations

import json
import re

from sentinel.models import Dependency, Ecosystem

_EXACT = re.compile(r"^\d+\.\d+\.\d+")


def _pinned(spec: str) -> str:
    """An npm spec pins a version only if it has no range operator."""
    spec = spec.strip()
    if spec and _EXACT.match(spec) and not spec[0] in "^~><=":
        return spec
    return ""


def parse_package_json(text: str, manifest_path: str = "package.json") -> list[Dependency]:
    try:
        data = json.loads(text)
    except Exception:
        return []

    deps: list[Dependency] = []

    for field_name, is_direct in (("dependencies", True), ("devDependencies", True)):
        section = data.get(field_name, {})
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            if not isinstance(spec, str):
                continue
            deps.append(
                Dependency(
                    name=name,
                    ecosystem=Ecosystem.NPM,
                    declared_spec=spec or "(unpinned)",
                    pinned_version=_pinned(spec),
                    is_direct=is_direct,
                    manifest_path=manifest_path,
                )
            )

    return deps