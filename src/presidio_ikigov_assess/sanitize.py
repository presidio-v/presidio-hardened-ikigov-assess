"""Input validation and output sanitisation for the IKI-Gov Assessment Tool.

All user-supplied strings are validated before use and HTML/shell-escaped
before being embedded in report output. No raw user input is ever echoed
into report templates or log entries without escaping.
"""

from __future__ import annotations

import html
import re
from datetime import datetime

from presidio_ikigov_assess.checklist import VALID_GATES, VALID_ITEM_IDS, VALID_RISK_CLASSES

_USE_CASE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LANG_ALLOWED = {"de", "en"}
_FORMAT_ALLOWED = {"markdown", "json"}


class ValidationError(ValueError):
    """Raised when a CLI parameter fails validation."""


def validate_use_case(value: str) -> str:
    """Validate and return a use-case name, raising ValidationError on failure."""
    if not value or not _USE_CASE_PATTERN.match(value):
        raise ValidationError(
            f"Invalid use-case name: '{_truncate(value)}'. "
            "Only alphanumeric characters, hyphens, and underscores are allowed (max 128 chars)."
        )
    return value


def validate_risk_class(value: str) -> str:
    v = value.strip().lower()
    if v not in VALID_RISK_CLASSES:
        raise ValidationError(
            f"Invalid risk class: '{_truncate(value)}'. Allowed: {', '.join(sorted(VALID_RISK_CLASSES))}."
        )
    return v


def validate_gate(value: str) -> str:
    v = value.strip().upper()
    if v not in VALID_GATES:
        raise ValidationError(
            f"Invalid gate: '{_truncate(value)}'. Allowed: {', '.join(sorted(VALID_GATES))}."
        )
    return v


def validate_lang(value: str) -> str:
    v = value.strip().lower()
    if v not in _LANG_ALLOWED:
        raise ValidationError(
            f"Invalid language: '{_truncate(value)}'. Allowed: {', '.join(sorted(_LANG_ALLOWED))}."
        )
    return v


def validate_format(value: str) -> str:
    v = value.strip().lower()
    if v not in _FORMAT_ALLOWED:
        raise ValidationError(
            f"Invalid format: '{_truncate(value)}'. Allowed: {', '.join(sorted(_FORMAT_ALLOWED))}."
        )
    return v


def validate_item_ids(raw: str) -> list[str]:
    """Parse and validate a comma-separated list of checklist item IDs."""
    if not raw or not raw.strip():
        return []
    ids = [tok.strip().upper() for tok in raw.split(",") if tok.strip()]
    if len(ids) > len(VALID_ITEM_IDS):
        raise ValidationError(
            f"Too many item IDs provided ({len(ids)}). Maximum is {len(VALID_ITEM_IDS)}."
        )
    for item_id in ids:
        if item_id not in VALID_ITEM_IDS:
            raise ValidationError(f"Unknown checklist item ID: '{_truncate(item_id)}'.")
    return ids


def escape_for_report(value: str) -> str:
    """HTML-escape a string for safe embedding in report output.

    NOTE: the primary defence against injection is *input* allow-listing
    (e.g. ``validate_use_case`` restricts names to ``[A-Za-z0-9_-]``); this
    output escaping is defence-in-depth. HTML-escaping alone does not neutralise
    Markdown link/image/table syntax — use :func:`escape_markdown` for fields
    rendered into Markdown.
    """
    return html.escape(str(value), quote=True)


# Markdown metacharacters that can inject structure (links, images, emphasis,
# code, tables, headings, lists). Backslash-escaped after HTML-escaping. ``&``,
# ``<`` and ``>`` are already entity-encoded by html.escape, so they are not
# repeated here; ``-``, ``.`` and ``_`` are intentionally omitted — they are
# inline-safe, appear in legitimate identifiers, and are already constrained by
# the input allow-lists (e.g. validate_use_case).
_MARKDOWN_SPECIALS = r"\`*{}[]()#+!|~"
_MARKDOWN_TRANSLATION = {ord(ch): f"\\{ch}" for ch in _MARKDOWN_SPECIALS}


def escape_markdown(value: str) -> str:
    """Escape a string for safe embedding in Markdown.

    HTML-escapes first (so the value is also safe if the Markdown is rendered to
    HTML), then backslash-escapes Markdown-significant characters so user-derived
    text cannot inject links, tables, or other structure. Defence-in-depth: the
    primary control remains input allow-listing.
    """
    return html.escape(str(value), quote=True).translate(_MARKDOWN_TRANSLATION)


_MAX_PATH_LEN = 4096


def validate_date(value: str) -> str:
    """Validate a YYYY-MM-DD date string (used for trend windows)."""
    v = value.strip()
    if not _DATE_PATTERN.match(v):
        raise ValidationError(f"Invalid date: '{_truncate(value)}'. Use format YYYY-MM-DD.")
    try:
        datetime.strptime(v, "%Y-%m-%d")
    except ValueError as exc:
        raise ValidationError(f"Invalid date: '{_truncate(value)}'. {exc}") from exc
    return v


def validate_output_path(value: str) -> str:
    """Validate a report output file path, raising ValidationError on failure.

    Bounds the length and rejects null bytes; the caller writes exactly where the
    user asks (their own CLI invocation), so no allow-list of locations is imposed.
    """
    v = value.strip()
    if not v:
        raise ValidationError("Output path must not be empty.")
    if "\x00" in v:
        raise ValidationError("Output path must not contain null bytes.")
    if len(v) > _MAX_PATH_LEN:
        raise ValidationError(f"Output path too long (max {_MAX_PATH_LEN} characters).")
    return v


def _truncate(value: str, max_len: int = 40) -> str:
    s = str(value)
    return s[:max_len] + "…" if len(s) > max_len else s
