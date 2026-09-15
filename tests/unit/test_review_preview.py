from pathlib import Path

from pii_redact.review.preview import confirm, render_preview_text
from pii_redact.types import PreviewSummary


def _preview(**kwargs) -> PreviewSummary:
    defaults = dict(
        document=Path("doc.csv"),
        counts_by_entity={},
        locations_by_entity={},
    )
    defaults.update(kwargs)
    return PreviewSummary(**defaults)


def test_render_preview_flags_unredactable_count_inline():
    preview = _preview(
        counts_by_entity={"PERSON": 3},
        locations_by_entity={"PERSON": []},
        unredactable_counts_by_entity={"PERSON": 1},
    )
    text = render_preview_text(preview)
    assert "PERSON: 3 occurrence(s)" in text
    assert "1 of these CANNOT be auto-redacted" in text
    assert "WARNING" in text


def test_render_preview_has_no_warning_when_nothing_unredactable():
    preview = _preview(counts_by_entity={"PERSON": 2}, locations_by_entity={"PERSON": []})
    text = render_preview_text(preview)
    assert "WARNING" not in text
    assert "CANNOT be auto-redacted" not in text


def test_confirm_non_interactive_refuses_when_unredactable_present():
    preview = _preview(
        counts_by_entity={"PERSON": 1},
        locations_by_entity={"PERSON": []},
        unredactable_counts_by_entity={"PERSON": 1},
    )
    assert confirm(preview, non_interactive=True) is False


def test_confirm_non_interactive_proceeds_when_nothing_unredactable():
    preview = _preview(counts_by_entity={"PERSON": 1}, locations_by_entity={"PERSON": []})
    assert confirm(preview, non_interactive=True) is True


def test_confirm_interactive_still_allows_informed_yes_despite_unredactable(monkeypatch):
    preview = _preview(
        counts_by_entity={"PERSON": 1},
        locations_by_entity={"PERSON": []},
        unredactable_counts_by_entity={"PERSON": 1},
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    assert confirm(preview, non_interactive=False) is True


def test_confirm_still_refuses_on_failed_sections_regardless_of_unredactable():
    preview = _preview(
        counts_by_entity={},
        locations_by_entity={},
        failed_pages_or_sections=["page 3: could not extract"],
    )
    assert confirm(preview, non_interactive=True) is False
