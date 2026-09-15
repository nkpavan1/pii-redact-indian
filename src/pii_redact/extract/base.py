"""Extractor interface. Each format module implements this and nothing else
- extract() must not know about detection, anonymization, or rendering, so
that adding a new format never touches recognizer logic (see project
instructions, "Keep the ingestion layer decoupled...").
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pii_redact.types import ExtractedDocument


class Extractor(ABC):
    @abstractmethod
    def extract(self, path: Path) -> ExtractedDocument:
        """Pull text + layout into an ExtractedDocument. Must raise rather
        than return a partial result on any page/sheet/section it can't
        parse - the pipeline's fail-closed policy depends on extraction
        failures being loud, not silently dropped."""
        raise NotImplementedError
