# Fuzzing

Coverage-guided fuzzing of `presidio-hardened-ikigov-assess` with
[Atheris](https://github.com/google/atheris). The harnesses drive the two
untrusted-input boundaries of the library and assert their fail-closed contracts:

- **`fuzz_classification.py`** — `classification.parse_classification_bytes`:
  the decode → JSON → validate → normalise path for `eai-classification/v1`
  producer documents. Asserts that only `ClassificationError` ever escapes, the
  L6/ecosystem normalisation invariants hold, parsing is deterministic, and the
  `level=L6` + `ecosystem=false` contradiction is always rejected.
- **`fuzz_evidence.py`** — `evidence.load_evidence` and
  `evidence.load_trust_store`: the peer evidence-document and trust-store
  loaders. Asserts that only `EvidenceError` escapes, parsed refs satisfy the
  string/hex field contract, `expected_signature` is deterministic, and a
  correctly-signed ref round-trips through `verify_ref`.

## Running locally

Atheris 3.x ships **manylinux** wheels for **CPython 3.12–3.14 only** — there is
no macOS or Windows wheel, and no cp310/cp311 wheel. Fuzz on **Linux under
Python 3.12**:

```bash
python3.12 -m venv .venv-fuzz
.venv-fuzz/bin/pip install '.[fuzz]'
.venv-fuzz/bin/python fuzz/fuzz_classification.py     # runs until a crash or Ctrl-C
.venv-fuzz/bin/python fuzz/fuzz_evidence.py
```

An editable install can shadow the built package on `sys.path`; install the
wheel (or confirm the import resolves to the installed distribution) so the code
under coverage is the code that ships.

## CI modes

The fuzz job runs on Linux/py3.12 in two modes:

- **Time-boxed smoke run** (per-PR): `-max_total_time=<seconds>` bounds each
  harness to a fixed CI budget so a fuzz regression fails fast.
- **Coverage/graceful-exit run**: `-atheris_runs=<N>` executes a fixed number of
  inputs and exits cleanly, emitting a coverage report instead of blocking on a
  crash.

```bash
python fuzz/fuzz_classification.py -max_total_time=60
python fuzz/fuzz_classification.py -atheris_runs=20000
```
