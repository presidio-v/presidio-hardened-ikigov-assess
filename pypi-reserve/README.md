# pypi-reserve — short-alias name reservation

The canonical package `presidio-hardened-ikigov-assess` ships for real via
`.github/workflows/publish.yml` (OIDC Trusted Publishing), so it needs no placeholder.

This directory only reserves the short public alias **`iki-gov`** so it cannot be squatted.
It ships no code — it builds a metadata-only empty wheel. The pre-release version
(`0.0.1.dev0`) means `pip install iki-gov` resolves nothing unless `--pre` is passed, so the
name is held without ever installing by accident.

## Reserve `iki-gov` (optional, one-time)

PyPI claims a name on first upload. Prereqs: a PyPI account with 2FA and an account-scoped
API token (PyPI → Account → API tokens).

```bash
python -m pip install --upgrade build twine
python -m build pypi-reserve/iki-gov
twine upload pypi-reserve/iki-gov/dist/*
# username: __token__   password: <account-scoped token>
```

At launch, decide whether `iki-gov` becomes a thin alias dist that depends on
`presidio-hardened-ikigov-assess`, or stays a reserved placeholder. Do **not** delete the
`0.0.1.dev0` release from PyPI (deleting frees the name and burns the version); leave it or
`yank` it.

`pypi-reserve/` is excluded from the real package's sdist, so nothing here ships in the
canonical distribution.

## Real release (canonical package)

See the repo root: bump `pyproject.toml` + `src/presidio_ikigov_assess/__init__.py` +
`CHANGELOG.md`, then push a signed `v*` tag. Before the **first** publish, register the
Trusted Publisher on PyPI (matching `presidio-v/presidio-hardened-ikigov-assess`,
workflow `publish.yml`, environment `release`) — for a not-yet-existing project use the
*pending publisher* flow.
