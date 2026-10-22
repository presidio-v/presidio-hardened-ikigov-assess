"""Build the IKI-Gov Assess user manual and slide deck in the PRESIDIO design.

    .venv/bin/python docs/marketing/build.py                 # HTML into docs/marketing/dist/
    .venv/bin/python docs/marketing/build.py --pdf           # + PDF via headless Chromium
    .venv/bin/python docs/marketing/build.py --lint ../vstantch-prose

Sources: manual.md (the prose), deck/project/ (the slides, the same files the Slides
artifact serves) and presidio.css (the presidio-web design tokens). The manual's
appendix is generated from the checklist in the package, so it cannot drift from the
code. Each output is one self-contained file: fonts and images are inlined, and a
Content-Security-Policy forbids scripts and every network fetch.
"""

import argparse
import base64
import html
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

from markdown_it import MarkdownIt

from presidio_ikigov_assess import __version__
from presidio_ikigov_assess.checklist import CHECKLIST

HERE = Path(__file__).resolve().parent
DIST = HERE / "dist"
PDF = HERE / "pdf"  # tracked: the published PDFs
ASSETS = HERE / "assets"
DECK = HERE / "deck" / "project"

CSP = "default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'"

# Asset ids in the Slides artifact -> the same files in this directory.
BLOBS = {
    "5b2e150cbce7bc6f33d3c5b2dcd4bbcd": "logo-blue.png",
    "d98026f69a93332b42c354d31c12e751": "logo-white.png",
    "612fc9c7d8ce4f55c9b63201e3088253": "bridge-blue.png",
    "a272754b8660eb22ca0d601258a1d09d": "bridge-white.png",
    "419a5e3339410b305af637f045edd042": "fonts/Inter-Variable.woff2",
    "604b14e98d4b4316b8bfdd929760a33b": "fonts/JetBrainsMono-Variable.woff2",
}


def data_uri(rel: str) -> str:
    path = ASSETS / rel
    mime = "font/woff2" if path.suffix == ".woff2" else mimetypes.guess_type(path.name)[0]
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"


def inline_css() -> str:
    css = (HERE / "presidio.css").read_text(encoding="utf-8")
    return re.sub(r"url\('assets/([^']+)'\)", lambda m: f"url('{data_uri(m.group(1))}')", css)


def page(title: str, head: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light">\n'
        f"<title>{html.escape(title)}</title>\n{head}</head>\n<body>\n{body}</body>\n</html>\n"
    )


# --- manual ------------------------------------------------------------------------


def appendix() -> str:
    rows = "\n".join(
        f"<tr><td>{i.id}</td><td>{html.escape(i.text_en)}</td>"
        f"<td>{i.m_dimension} · {', '.join(i.gates)}</td></tr>"
        for i in CHECKLIST
    )
    return (
        '<h2 id="appendix">Appendix: the 25 checklist items</h2>\n'
        "<p>Generated from the checklist in the installed package. "
        "The last column names the measurement dimension and the gates each item feeds.</p>\n"
        '<table class="appendix">\n<thead><tr><th>ID</th><th>Item</th>'
        "<th>Feeds</th></tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n</table>\n"
    )


def build_manual() -> Path:
    source = (HERE / "manual.md").read_text(encoding="utf-8")
    title_line, _, rest = source.partition("\n")
    title = title_line.removeprefix("# ").strip()
    product, _, subtitle = title.partition(": ")
    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    body = (
        '<header class="site-header"><div class="site-header__row">'
        f'<img src="{data_uri("logo-blue.png")}" alt="PRESIDIO" width="140" height="28">'
        f'<span class="site-header__meta">v{__version__}</span></div></header>\n'
        '<main class="manual">\n<section class="hero">'
        f'<img class="hero__motif" src="{data_uri("bridge-blue.png")}" alt="">'
        f'<p class="eyebrow">{html.escape(subtitle or "Manual")}</p>'
        f"<h1>{html.escape(product)}</h1></section>\n"
        f"{md.render(rest)}{appendix()}</main>\n"
        '<footer class="site-footer"><div class="site-footer__row">'
        "<p>© PRESIDIO OOD · Sofia, BG</p>"
        "<p>presidio-group.eu · MIT licence</p></div></footer>\n"
    )
    out = DIST / "manual.html"
    out.write_text(page(title, f"<style>\n{inline_css()}</style>\n", body), encoding="utf-8")
    return out


# --- slides ------------------------------------------------------------------------

SLIDE_CSS = """
@page { size: 1920px 1080px; margin: 0; }
body { margin: 0; background: #14171c; }
section { position: relative; width: 1920px; height: 1080px; overflow: hidden;
  box-sizing: border-box; margin: 0 auto 32px; break-after: page; }
section * { margin: 0; box-sizing: border-box; }
section aside { display: none; }
section img { display: block; }
section table { border-collapse: collapse; width: 100%; }
section th, section td { border-bottom: 1px solid #e5e7eb; vertical-align: top; }
section th { font-weight: 600; }
@media print { section { margin: 0; } }
"""


def _cell_padding(section: str) -> str:
    """The slide format puts cell padding on the <table>; a browser needs it on the cells."""

    def fix(m: re.Match) -> str:
        table = m.group(0)
        pad = re.search(r"padding:([^;\"]+);?", table.split(">", 1)[0])
        if not pad:
            return table
        table = table.replace(pad.group(0), "", 1)
        cell_pad = f"padding:{pad.group(1)};"
        table = re.sub(r'<(td|th) style="', rf'<\1 style="{cell_pad}', table)
        return re.sub(r"<(td|th)>", rf'<\1 style="{cell_pad}">', table)

    return re.sub(r"<table\b.*?</table>", fix, section, flags=re.S)


def build_slides() -> tuple[Path, list[Path]]:
    deck = json.loads((DECK / "deck.json").read_text(encoding="utf-8"))
    files = [DECK / "slides" / f"{slide_id}.html" for slide_id in deck["order"]]
    sections = []
    for f in files:
        s = _cell_padding(f.read_text(encoding="utf-8"))
        s = re.sub(r"/_blob/([0-9a-f]{32})", lambda m: data_uri(BLOBS[m.group(1)]), s)
        sections.append(s)
    faces = "".join(
        f"@font-face {{ font-family: '{face['family']}'; font-weight: 100 900; "
        f"src: url('{data_uri(BLOBS[face['src'].removeprefix('/_blob/')])}') format('woff2'); }}\n"
        for face in deck["faces"].values()
    )
    out = DIST / "slides.html"
    head = f"<style>\n{faces}{SLIDE_CSS}</style>\n"
    out.write_text(page(deck["title"], head, "\n".join(sections)), encoding="utf-8")
    return out, files


# --- PDF -----------------------------------------------------------------------------


def find_chrome() -> str:
    if os.environ.get("CHROME"):
        return os.environ["CHROME"]
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        if found := shutil.which(name):
            return found
    pw = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"))
    for candidate in sorted(pw.glob("chromium-*/chrome-linux/chrome"), reverse=True):
        return str(candidate)
    sys.exit("No Chromium found; set CHROME to its path.")


def print_pdf(chrome: str, src: Path) -> Path:
    PDF.mkdir(exist_ok=True)
    out = PDF / f"iki-gov-assess-{src.stem}.pdf"
    with tempfile.TemporaryDirectory() as profile:
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=10000",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={out}",
            src.as_uri(),
        ]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(1, "--no-sandbox")  # Chromium refuses to run as root otherwise.
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return out


# --- prose lint ------------------------------------------------------------------------


class _Prose(HTMLParser):
    """Reader-visible text of a slide, one block per line; code and monospace skipped."""

    BLOCK = {"p", "h1", "h2", "h3", "li", "td", "th"}
    SKIP = {"aside", "code", "pre", "script", "style"}
    VOID = {"br", "img", "hr", "meta", "link"}

    def __init__(self) -> None:
        super().__init__()
        self.blocks: list[str] = []
        self._buf: list[str] = []
        self._stack: list[tuple[str, bool]] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        skip = tag in self.SKIP or "Mono" in (dict(attrs).get("style") or "")
        self._skip += skip
        self._stack.append((tag, skip))
        if tag in self.BLOCK:
            self._flush()

    def handle_endtag(self, tag):
        while self._stack:
            open_tag, skip = self._stack.pop()
            self._skip -= skip
            if open_tag == tag:
                break
        if tag in self.BLOCK:
            self._flush()

    def handle_data(self, data):
        if not self._skip:
            self._buf.append(data)

    def _flush(self) -> None:
        if text := " ".join("".join(self._buf).split()):
            self.blocks.append(text)
        self._buf = []


def lint(prose_repo: Path, slide_files: list[Path]) -> bool:
    parser = _Prose()
    for f in slide_files:
        parser.feed(f.read_text(encoding="utf-8"))
    slide_text = DIST / "slides-text.md"
    slide_text.write_text("\n\n".join(parser.blocks) + "\n", encoding="utf-8")
    # The linter needs PyYAML, which this package does not: prefer the prose repo's venv.
    venv = prose_repo / ".venv" / "bin" / "python"
    python = str(venv) if venv.exists() else os.environ.get("PROSE_PYTHON", "python3")
    ok = True
    for draft in (HERE / "manual.md", slide_text):
        result = subprocess.run([python, str(prose_repo / "query" / "lint.py"), str(draft)])
        ok &= result.returncode == 0
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pdf", action="store_true", help="also print PDFs with headless Chromium")
    ap.add_argument(
        "--lint", type=Path, metavar="PROSE_REPO", help="lint the text with vstantch-prose"
    )
    args = ap.parse_args()

    DIST.mkdir(exist_ok=True)
    outputs = [build_manual()]
    slides, slide_files = build_slides()
    outputs.append(slides)
    if args.pdf:
        chrome = find_chrome()
        outputs += [print_pdf(chrome, out) for out in list(outputs)]
    for out in outputs:
        print(out.relative_to(HERE.parent.parent))
    if args.lint and not lint(args.lint.resolve(), slide_files):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
