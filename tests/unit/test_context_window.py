from pii_redact.pipeline import _context_window, _merge_detections
from pii_redact.types import Detection, Location, TextBlock


def _block(text, page=0, bbox=None):
    return TextBlock(text=text, location=Location(page=page, bbox=bbox))


def _detection(entity_type, start, end, score=0.85):
    return Detection(
        entity_type=entity_type, start=start, end=end, score=score,
        block_index=0, location=Location(page=0),
    )


# --- _context_window: neighbors are found by VISUAL position (bbox), not
# list order - the bug this specifically guards against: a real AIS PDF's
# extraction order does not match its visual layout (see pipeline.py's
# docstring for why), so a naive "blocks[index-1]/blocks[index+1]" version
# of this function silently paired blocks with the wrong neighbor. Every
# test here places blocks in a bbox order that DIFFERS from list order.


def _stacked(text, y, page=0):
    # A block occupying one vertical "line" at height y, all at the same
    # x position - bbox = (x0, y0, x1, y1).
    return _block(text, page=page, bbox=(10, y, 100, y + 20))


def test_block_without_bbox_gets_no_neighbors():
    blocks = [_block("only line")]  # no bbox
    window, offset = _context_window(blocks, 0)
    assert window == "only line"
    assert offset == 0


def test_neighbors_found_by_visual_position_not_list_order():
    # List order deliberately scrambled: "value" (y=20, visually SECOND)
    # appears FIRST in the list; "label" (y=0, visually FIRST) appears
    # SECOND. A naive list-adjacency version would treat these as
    # neighbors of whatever happens to sit next to them in the list
    # instead of what's actually above/below them on the page. "buffer"
    # keeps "unrelated" outside the default radius=1 window so this test
    # isolates the list-order-vs-visual-order question specifically.
    blocks = [
        _stacked("value", y=20),       # index 0, visually 2nd from top
        _stacked("label", y=0),        # index 1, visually 1st (topmost)
        _stacked("buffer", y=40),      # index 2, visually 3rd
        _stacked("unrelated", y=200),  # index 3, far below, not a neighbor
    ]
    window, offset = _context_window(blocks, 0)  # analyzing "value" (index 0)
    assert window == "label | value | buffer"
    assert window[offset : offset + len("value")] == "value"


def test_includes_previous_and_next_by_vertical_position():
    blocks = [
        _stacked("before", y=0),
        _stacked("current", y=20),
        _stacked("after", y=40),
    ]
    window, offset = _context_window(blocks, 1)
    assert window == "before | current | after"
    assert window[offset : offset + len("current")] == "current"


def test_topmost_block_has_no_before_neighbor():
    blocks = [_stacked("current", y=0), _stacked("after", y=20)]
    window, offset = _context_window(blocks, 0)
    assert window == "current | after"
    assert offset == 0


def test_bottommost_block_has_no_after_neighbor():
    blocks = [_stacked("before", y=0), _stacked("current", y=20)]
    window, offset = _context_window(blocks, 1)
    assert window == "before | current"
    assert window[offset:] == "current"


def test_does_not_cross_page_boundary():
    blocks = [_stacked("page0 line", y=0, page=0), _stacked("page1 line", y=20, page=1)]
    window, offset = _context_window(blocks, 1)
    assert window == "page1 line"
    assert offset == 0


def test_default_radius_only_includes_immediate_vertical_neighbors():
    blocks = [_stacked("A", y=0), _stacked("B", y=20), _stacked("C", y=40), _stacked("D", y=60)]
    # radius default is 1: only "B" (immediately above "C") counts.
    window, offset = _context_window(blocks, 2)
    assert window == "B | C | D"
    assert window[offset : offset + 1] == "C"


def test_wider_radius_includes_more_vertical_neighbors():
    blocks = [_stacked("A", y=0), _stacked("B", y=20), _stacked("C", y=40), _stacked("D", y=60)]
    window, offset = _context_window(blocks, 2, radius=2)
    assert window == "A | B | C | D"
    assert window[offset : offset + 1] == "C"


def test_same_row_only_nearest_neighbor_within_radius_is_included():
    # Same-row (label-left/value-right) relationships ARE valid neighbors -
    # see test_label_left_value_right_same_row_layout_shares_context below
    # for why: a real bank interest certificate lays every field out this
    # way, and the column-only version of this function gave such a value
    # zero context. This test guards the radius limit on that new search:
    # with radius=1, only the NEAREST same-row block on each side counts,
    # not every block in the row.
    far_left = _block("far_left", bbox=(10, 0, 50, 20))
    near_left = _block("near_left", bbox=(60, 0, 100, 20))
    current = _block("current", bbox=(110, 0, 150, 20))
    blocks = [current, far_left, near_left]
    window, offset = _context_window(blocks, 0, radius=1)
    assert window == "near_left | current"
    assert "far_left" not in window


def test_label_left_value_right_same_row_layout_shares_context():
    # The exact real bug this extension fixes: a bank interest certificate
    # lays every field out as "Label : Value" side by side on ONE row (e.g.
    # "Customer Id" then "10023456" immediately to its right, same Y) - the
    # opposite relationship from AIS's label-above-value layout. The value
    # has no same-COLUMN neighbor at all (nothing stacked above/below it),
    # so without a same-ROW search it would get zero context and every
    # context-scoped recognizer would miss it entirely.
    label = _block("Customer Id", bbox=(70.9, 274.2, 130.8, 289.3))
    value = _block("10023456", bbox=(198.4, 274.2, 247.4, 289.3))
    blocks = [value, label]
    window, offset = _context_window(blocks, 0)
    assert window == "Customer Id | 10023456"
    assert window[offset:] == "10023456"


def test_three_column_table_value_finds_label_in_same_column_plus_row_neighbors():
    # The exact real bug this originally fixed: a 3-column label row
    # followed by a 3-column value row (a real AIS document's actual
    # layout). The "Date of Birth" value in column 1 must still pair with
    # "Date of Birth" (directly above it, same column) - NOT with
    # "E-mail Address" (column 3's label, one row up, which is what a flat
    # top-to-bottom/left-to-right sort would have picked as "nearest").
    # Same-row values from other columns are now ALSO pulled in by the
    # same-row search added for the label-beside-value layout above - that
    # is harmless extra context here, since it's just other unrelated
    # VALUES (not a wrong label) sharing the window.
    col1_label = _block("Date of Birth", bbox=(10, 100, 90, 120))
    col2_label = _block("Mobile Number", bbox=(150, 100, 230, 120))
    col3_label = _block("E-mail Address", bbox=(290, 100, 370, 120))
    col1_value = _block("15/08/1990", bbox=(10, 130, 90, 150))
    col2_value = _block("9876543210", bbox=(150, 130, 230, 150))
    col3_value = _block("person@example.com", bbox=(290, 130, 370, 150))
    blocks = [col3_label, col1_value, col2_label, col3_value, col1_label, col2_value]

    dob_index = blocks.index(col1_value)
    window, offset = _context_window(blocks, dob_index)
    assert window == "Date of Birth | 15/08/1990 | 9876543210"
    assert "E-mail" not in window
    assert window[offset : offset + len("15/08/1990")] == "15/08/1990"

    mobile_index = blocks.index(col2_value)
    window2, offset2 = _context_window(blocks, mobile_index)
    assert window2 == "15/08/1990 | Mobile Number | 9876543210 | person@example.com"


# --- _merge_detections: widened context can only add/grow, never shrink ---


def test_merge_keeps_base_detection_when_windowed_has_nothing_overlapping():
    base = [_detection("PERSON", 0, 18)]
    merged = _merge_detections(base, [])
    assert merged == base


def test_merge_adds_windowed_only_detection_with_no_overlap():
    base = [_detection("PERSON", 0, 18)]
    windowed = [_detection("IN_DATE_OF_BIRTH", 30, 40)]
    merged = _merge_detections(base, windowed)
    assert len(merged) == 2
    assert windowed[0] in merged


def test_merge_prefers_larger_windowed_span_over_smaller_base_span():
    # Real scenario this fixes: base pass alone found only "KUMAR SHARMA"
    # (7..18), windowed pass found the full "RAHUL KUMAR SHARMA" (0..18) -
    # the larger span must win.
    base = [_detection("PERSON", 7, 18)]
    windowed = [_detection("PERSON", 0, 18)]
    merged = _merge_detections(base, windowed)
    assert len(merged) == 1
    assert merged[0].start == 0 and merged[0].end == 18


def test_merge_keeps_larger_base_span_over_smaller_windowed_span():
    # The mirror image: base found the full name, windowed (for whatever
    # reason) found only a truncated version - base must win, never shrink.
    base = [_detection("PERSON", 0, 18)]
    windowed = [_detection("PERSON", 7, 18)]
    merged = _merge_detections(base, windowed)
    assert len(merged) == 1
    assert merged[0].start == 0 and merged[0].end == 18


def test_merge_does_not_conflate_different_entity_types_at_same_span():
    base = [_detection("PERSON", 0, 10)]
    windowed = [_detection("IN_PAN", 0, 10)]
    merged = _merge_detections(base, windowed)
    assert len(merged) == 2
