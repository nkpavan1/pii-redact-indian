"""Renderer interface: takes the extracted document plus the anonymized
replacement text per block, and writes the output artifact in the same
format as the input (see project instructions: never flatten a PDF to an
image, never lose formulas that don't touch redacted cells, etc.)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pii_redact.types import ExtractedDocument


class Renderer(ABC):
    @abstractmethod
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        """replacements maps TextBlock index (into extracted.blocks) to its
        final anonymized text. Blocks with no entry are written back
        unchanged."""
        raise NotImplementedError
