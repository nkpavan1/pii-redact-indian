"""Plain-text / markdown extraction (.txt, .md, .markdown).

One block per paragraph (a maximal run of non-blank lines), not per line:
a paragraph is the natural unit of sentence context for NER and for
Presidio's context-word boosting, and a name wrapped across two lines of
the same paragraph still reaches the analyzer as one span.

Every block records its exact character span in the decoded source text
(`source_ref = (start, end)`), so render/text.py can splice replacements
back in place and leave every other byte - headings, blank lines, line
endings, frontmatter delimiters - exactly as it was. Frontmatter is not
parsed specially here; its lines are just another paragraph to scan.
"""

from __future__ import annotations

import re
from pathlib import Path

from pii_redact.extract.base import Extractor

# Shared with the CSV path: same small, ordered encoding list and the same
# BOM handling, so a note saved by a legacy Windows editor decodes (and
# round-trips on write) the same way a legacy CSV export does.
from pii_redact.extract.csv_ import _read_text
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock

# A line with at least one non-whitespace character, followed by any number
# of further such lines. [^\r\n] rather than "." so a CRLF file's "\r" never
# ends up inside a block's text.
_PARAGRAPH = re.compile(r"[^\S\r\n]*\S[^\r\n]*(?:\r?\n[^\S\r\n]*\S[^\r\n]*)*")


class TextExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        text, encoding = _read_text(path)

        blocks: list[TextBlock] = []
        for match in _PARAGRAPH.finditer(text):
            blocks.append(
                TextBlock(
                    text=match.group(0),
                    location=Location(row=text.count("\n", 0, match.start())),
                    source_ref=(match.start(), match.end()),
                )
            )

        return ExtractedDocument(
            doc_format=DocFormat.TEXT,
            source_path=path,
            blocks=blocks,
            format_metadata={"encoding": encoding},
        )
