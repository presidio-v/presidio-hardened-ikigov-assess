"""server.json must stay publishable to the MCP Registry.

The registry rejects a publish whose version differs from the PyPI release or
whose description exceeds 100 characters, and it proves namespace ownership by
finding the ``mcp-name`` marker in the PyPI README. A drift in any of these
surfaces only after the tag, when PyPI has already accepted the release, so the
checks run here instead.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from presidio_ikigov_assess import __version__

ROOT = Path(__file__).resolve().parent.parent
SERVER = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
PACKAGE = SERVER["packages"][0]


def test_versions_match_package() -> None:
    assert SERVER["version"] == __version__
    assert PACKAGE["version"] == __version__
    assert PACKAGE["runtimeArguments"][0]["value"] == (
        f"presidio-hardened-ikigov-assess[mcp]=={__version__}"
    )


def test_description_within_registry_limit() -> None:
    assert len(SERVER["description"]) <= 100


def test_readme_carries_mcp_name_marker() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"<!-- mcp-name: {SERVER['name']} -->" in readme


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is 3.11+")
def test_identifier_is_a_console_script_running_the_server() -> None:
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert PACKAGE["identifier"] == pyproject["project"]["name"]
    assert scripts[PACKAGE["identifier"]] == scripts["iga-mcp"]
