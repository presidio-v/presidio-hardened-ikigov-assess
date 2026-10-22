# Marketing deck and user manual

Collateral for IKI-Gov Assess in the PRESIDIO design (tokens from `presidio-web`).

| Source | What it is |
|---|---|
| `manual.md` | The user manual. The appendix is generated from the package checklist. |
| `deck/project/` | The slide deck: one HTML section per slide, ordered by `deck.json`. The same files back the Slides artifact. |
| `presidio.css` | Design tokens and manual styles. |
| `assets/` | Logo, bridge motif and the vendored Inter and JetBrains Mono fonts (SIL OFL 1.1). |

The published PDFs are in `pdf/`; the PRESIDIO website links to them there.
Rebuild them after any change to a source, and commit the result. The HTML goes to
`dist/`, which git ignores:

```bash
.venv/bin/python docs/marketing/build.py --pdf --lint ../vstantch-prose
```

`--pdf` needs a Chromium; set `CHROME` if it is not on `PATH`. `--lint` runs the
`vstantch-prose` linter over the manual and the visible slide text, code excluded,
and exits 1 on any finding. The outputs load nothing from the network: fonts and
images are inlined and a Content-Security-Policy blocks scripts and fetches.

The slide files use the Slides artifact's asset URLs (`/_blob/<id>`); `build.py`
maps each id to its file in `assets/`. A new image needs an entry in `BLOBS`.
