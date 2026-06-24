"""Interactive wizard for guided step-by-step IKI-Gov assessment.

Uses prompt_toolkit for rich interactive input with history support.
Each of the 25 checklist items is presented in sequence with:
  - Progress indicator (Item X/25 — Section: …)
  - Item text in the selected language
  - Y/N/S/? prompt (or J/N/Ü/? in German)
  - Inline help on ?
"""

from __future__ import annotations

from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.styles import Style

from presidio_ikigov_assess.checklist import CHECKLIST, ChecklistItem
from presidio_ikigov_assess.i18n import section_name, t

_WIZARD_STYLE = Style.from_dict(
    {
        "progress": "bold cyan",
        "section": "bold",
        "question": "",
        "prompt": "bold green",
        "help": "italic grey",
    }
)

_YES_TOKENS = {"y", "j", "yes", "ja"}
_NO_TOKENS = {"n", "no", "nein"}
_SKIP_TOKENS = {"s", "ü", "u", "skip", "überspringen"}
_HELP_TOKEN = "?"  # nosec B105 — interactive help-command token, not a credential


def _item_help(item: ChecklistItem, lang: str) -> str:
    """Return inline help text explaining the item's governance context.

    The mapping (dimension + gates) is language-neutral, so the same line is
    shown regardless of *lang*.
    """
    gate_list = ", ".join(item.gates)
    return f"Dimension: {item.m_dimension}  |  Gates: {gate_list}"


def run_wizard(
    lang: str,
    risk_class: str,
    use_case: str,
) -> tuple[frozenset[str], frozenset[str]]:
    """Run the interactive wizard and return (affirmed_ids, skipped_ids).

    The wizard iterates all 25 checklist items and records Y/N/Skip answers.
    Returns two frozensets — affirmed item IDs and skipped item IDs.
    All other items are implicitly denied.
    """
    affirmed: list[str] = []
    skipped: list[str] = []
    total = len(CHECKLIST)

    welcome = t("wizard_welcome", lang)
    print(f"\n{welcome}\n")

    for idx, item in enumerate(CHECKLIST, start=1):
        section = section_name(item.id, lang)
        progress = t("wizard_progress", lang, current=idx, total=total, section=section)
        item_text = item.text(lang)
        wizard_prompt = t("wizard_prompt", lang)

        print(f"\n[{progress}]")
        print(f"  {item.id}. {item_text}")

        while True:
            try:
                raw = pt_prompt(wizard_prompt).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                raise

            if raw in _YES_TOKENS:
                affirmed.append(item.id)
                break
            elif raw in _NO_TOKENS:
                break  # denied — not added to either set
            elif raw in _SKIP_TOKENS:
                skipped.append(item.id)
                break
            elif raw == _HELP_TOKEN:
                help_text = _item_help(item, lang)
                prefix = t("wizard_help_prefix", lang)
                print(f"{prefix}{help_text}")
            else:
                print(t("wizard_invalid", lang))

    affirmed_count = len(affirmed)
    denied_count = total - affirmed_count - len(skipped)
    summary = t(
        "wizard_summary",
        lang,
        affirmed=affirmed_count,
        denied=denied_count,
        skipped=len(skipped),
    )
    print(f"\n{summary}\n")

    return frozenset(affirmed), frozenset(skipped)
