"""Ecosystem parsers. Each turns a manifest file into a list of Dependencies.

The registry of parsers is keyed by filename so discovery can match a found
file to the right parser. Adding an ecosystem means adding a parser module and
registering it here -- nothing else changes.
"""

from __future__ import annotations

from collections.abc import Callable

from sentinel.models import Dependency
from sentinel.parsers import node, python

# Parser signature: (text, manifest_path) -> list[Dependency]
Parser = Callable[[str, str], list[Dependency]]

# Keyed by manifest filename. Discovery matches found files against these keys.
PARSERS: dict[str, Parser] = {
    "requirements.txt": python.parse_requirements,
    "pyproject.toml": python.parse_pyproject,
    "package.json": node.parse_package_json,
}


def parser_for(filename: str) -> Parser | None:
    return PARSERS.get(filename)


def known_manifest_names() -> tuple[str, ...]:
    return tuple(PARSERS.keys())