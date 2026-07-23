<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 PRESIDIO Group -->
# Hash-pinned CI toolchains

These `*.txt` files are `--require-hashes` lockfiles for the standalone tools the
CI/release workflows install with `pip`. Pinning by hash satisfies the OpenSSF
Scorecard **Pinned-Dependencies** check and stops a compromised package index
from substituting a build backend, publisher, or SBOM generator.

| File | Tools | Used by |
|---|---|---|
| `ci-toolchain.txt` | pip, setuptools, wheel | `pytest.yml` (matrix 3.10–3.12) |
| `release-build.txt` | pip, build | `publish.yml`, `reserve-iki-gov.yml` |
| `twine.txt` | twine | `publish.yml` (metadata check) |
| `cyclonedx.txt` | cyclonedx-bom | `publish.yml` (SBOM) |

The `-e ".[dev]"` editable install in `pytest.yml` is intentionally **not**
hash-pinned: it installs the local project plus dev extras resolved from
`pyproject.toml`, not a fixed remote artifact.

## Regenerate

Universal (cross-Python 3.10+) resolution with hashes, via `uv`:

```bash
cd .github/constraints
for base in ci-toolchain release-build twine cyclonedx; do
  uv pip compile --generate-hashes --universal --python-version 3.10 \
    --annotation-style=line "$base.in" -o "$base.txt"
done
```

Bump a tool by editing the matching `*.in` and re-running the loop. Validate a
file resolves under `--require-hashes` before committing:

```bash
uv venv --python 3.12 /tmp/v && VIRTUAL_ENV=/tmp/v \
  uv pip install --dry-run --require-hashes -r cyclonedx.txt
```
