"""Standalone image re-rendering (JPEG/PNG).

Per-region redaction only: blackens each redacted line's bbox and draws
the replacement text on top (Pillow's built-in default font - no extra
font-file dependency). Does NOT implement full-image blackout for
sensitive document types (id_card_scan) - see extract/image.py's KNOWN,
UNMITIGATED GAP note; that policy needs the caller to pass doc_type
through, which Renderer.render()'s signature doesn't currently carry, and
extending it is a deliberately deferred decision (see that module).

Unlike PDF redaction, drawing replacement text onto a raster image doesn't
create genuinely "searchable" text - a JPEG/PNG has no text layer at all -
it's purely for human/LLM-vision readability of the redacted output, not a
machine-extractable improvement the way PDF's redact-and-replace is.

Known cosmetic limitation: Pillow's default font is small and fixed-size;
replacement text may overflow a bbox that was sized for shorter/longer
original text. Not a correctness issue (the black box always fully covers
the original region regardless), just not pixel-perfect typography.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, UnidentifiedImageError

from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument

_TEXT_PADDING = 2


class ImageRenderError(ValueError):
    pass


class ImageRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        try:
            image = Image.open(source_path).convert("RGB")
        except (UnidentifiedImageError, OSError) as exc:
            raise ImageRenderError(f"{source_path}: could not open image ({exc})") from exc

        draw = ImageDraw.Draw(image)
        font = ImageFont.load_default()

        for block_index, new_text in replacements.items():
            if block_index >= len(extracted.blocks):
                raise ImageRenderError(
                    f"block {block_index}: does not exist in the extracted document"
                )
            block = extracted.blocks[block_index]
            bbox = block.location.bbox
            if bbox is None:
                raise ImageRenderError(f"block {block_index}: missing bbox for redaction")

            draw.rectangle(bbox, fill=(0, 0, 0))
            draw.text(
                (bbox[0] + _TEXT_PADDING, bbox[1] + _TEXT_PADDING),
                new_text,
                fill=(255, 255, 255),
                font=font,
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(output_path)
