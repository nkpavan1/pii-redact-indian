"""Requires presidio-analyzer to be installed (`pip install -e .[dev]`) -
skips cleanly otherwise so the rest of the suite stays runnable without the
full ML dependency stack.

No GSTIN/CreditCard tests here - both are covered by Presidio's own
built-ins now (InGstinRecognizer, CreditCardRecognizer) rather than
project-custom duplicates - see detect/recognizers/__init__.py.
"""

import re

import pytest

pytest.importorskip("presidio_analyzer")

from pii_redact.detect.recognizers.identity_numbers import TanRecognizer
from pii_redact.detect.recognizers.banking import IfscRecognizer
from pii_redact.detect.recognizers.dates import DateOfBirthRecognizer
from pii_redact.detect.recognizers.ais import AisDownloadIdRecognizer
from pii_redact.detect.recognizers.address import AddressRecognizer


def _regex(recognizer_cls, pattern_index=0):
    return re.compile(recognizer_cls.PATTERNS[pattern_index].regex)


def test_tan_pattern_matches_synthetic_tan():
    assert _regex(TanRecognizer).search("ABCD12345E")


def test_ifsc_pattern_matches_synthetic_ifsc():
    assert _regex(IfscRecognizer).search("HDFC0001234")


def test_ifsc_pattern_requires_zero_in_fifth_position():
    assert not _regex(IfscRecognizer).fullmatch("HDFC1001234")


def test_dob_numeric_pattern_matches_common_formats():
    numeric = _regex(DateOfBirthRecognizer, 0)
    assert numeric.search("15/08/1990")
    assert numeric.search("15-08-1990")
    assert numeric.search("15.08.1990")


def test_dob_iso_pattern_matches():
    iso = _regex(DateOfBirthRecognizer, 1)
    assert iso.search("1990-08-15")


def test_dob_day_month_year_pattern_matches():
    day_month = _regex(DateOfBirthRecognizer, 2)
    assert day_month.search("15 August 1990")
    assert day_month.search("15-Aug-1990")


def test_dob_month_day_year_pattern_matches():
    month_day = _regex(DateOfBirthRecognizer, 3)
    assert month_day.search("August 15, 1990")


def test_dob_day_month_year_rejects_quarter_range():
    # Real user report on an AIS document: "Q4(Jan-Mar)" must never match.
    day_month = _regex(DateOfBirthRecognizer, 2)
    assert not day_month.search("Q4(Jan-Mar)")
    assert not day_month.search("Jan-Mar 15 1990")


def test_dob_month_day_year_rejects_quarter_range():
    month_day = _regex(DateOfBirthRecognizer, 3)
    assert not month_day.search("Jan - Mar 1990")


def test_ais_download_id_pattern_matches_synthetic_id():
    assert _regex(AisDownloadIdRecognizer).fullmatch("ABCDE1234F202501151030")


def test_ais_download_id_validate_result_accepts_plausible_date_time():
    r = AisDownloadIdRecognizer()
    assert r.validate_result("ABCDE1234F202501151030") is True


@pytest.mark.parametrize(
    "download_id",
    [
        "ABCDE1234F202513151030",  # month 13
        "ABCDE1234F202501321030",  # day 32
        "ABCDE1234F202501152530",  # hour 25
        "ABCDE1234F189901151030",  # year 1899
    ],
)
def test_ais_download_id_validate_result_rejects_implausible_date_time(download_id):
    r = AisDownloadIdRecognizer()
    assert r.validate_result(download_id) is False


def test_in_pan_does_not_match_inside_ais_download_id():
    # The gap this recognizer exists to close - confirmed directly, not
    # assumed: IN_PAN's trailing \b never matches because digits
    # immediately follow the embedded PAN's last letter (no boundary).
    from presidio_analyzer.predefined_recognizers import InPanRecognizer

    pan_recognizer = InPanRecognizer()
    test_id = "ABCDE1234F202501151030"
    assert not any(re.search(p.regex, test_id) for p in pan_recognizer.patterns)


def test_address_pattern_matches_real_indian_address():
    pattern = re.compile(AddressRecognizer.PATTERNS[0].regex)
    address = "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH"
    match = pattern.search(address)
    assert match is not None
    assert match.group(0) == address


def test_address_pattern_requires_minimum_length():
    pattern = re.compile(AddressRecognizer.PATTERNS[0].regex)
    assert not pattern.search("short")
