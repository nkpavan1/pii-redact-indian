"""Plain-text / markdown extraction (.txt, .md, .markdown).

One block per paragraph (a maximal run of non-blank lines), not per line:
a paragraph is the natural unit of sentence context for NER and for
Presidio's context-word boosting, and a name wrapped across two lines of
the same paragraph still reaches the analyzer as one span. Fenced code
blocks are just more paragraphs here - scanned like everything else, and
(because rendering splices spans back in place) otherwise left verbatim.

Markdown frontmatter (a leading `---` ... `---` or `...` block in a .md
file) is the exception: one block per line, so each `key: value` line is
analyzed on its own and its key acts as the context word for its value
(`dob: 15/08/1990`) without boosting a neighboring line's value. Delimiter
lines are never blocks. An unclosed `---` block is not frontmatter and is
scanned as ordinary text.

Every block records its exact character span in the decoded source text
(`source_ref = (start, end)`), so render/text.py can splice replacements
back in place and leave every other byte - headings, blank lines, line
endings, frontmatter delimiters - exactly as it was.
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
_LINE = re.compile(r"[^\S\r\n]*\S[^\r\n]*")

_FRONTMATTER_SUFFIXES = {".md", ".markdown"}
_FRONTMATTER_OPEN = "---"
_FRONTMATTER_CLOSE = {"---", "..."}


def frontmatter_bounds(text: str) -> tuple[int, int, int] | None:
    """(content_start, content_end, body_start) character offsets when
    `text` opens with a closed frontmatter block, else None."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip() != _FRONTMATTER_OPEN:
        return None
    offset = content_start = len(lines[0])
    for line in lines[1:]:
        if line.rstrip() in _FRONTMATTER_CLOSE:
            return content_start, offset, offset + len(line)
        offset += len(line)
    return None


def _block(text: str, match: re.Match) -> TextBlock:
    return TextBlock(
        text=match.group(0),
        location=Location(row=text.count("\n", 0, match.start())),
        source_ref=(match.start(), match.end()),
    )


class TextExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        text, encoding = _read_text(path)

        blocks: list[TextBlock] = []
        body_start = 0
        if path.suffix.lower() in _FRONTMATTER_SUFFIXES:
            bounds = frontmatter_bounds(text)
            if bounds is not None:
                content_start, content_end, body_start = bounds
                blocks.extend(_block(text, m) for m in _LINE.finditer(text, content_start, content_end))
        blocks.extend(_block(text, m) for m in _PARAGRAPH.finditer(text, body_start))

        return ExtractedDocument(
            doc_format=DocFormat.TEXT,
            source_path=path,
            blocks=blocks,
            format_metadata={"encoding": encoding},
        )
