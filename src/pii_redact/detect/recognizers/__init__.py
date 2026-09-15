"""Custom PatternRecognizers not covered by Presidio's built-ins.

`get_custom_recognizers()` returns everything analyzer.py should register.
`AADHAAR_REPLACEMENT_ENTITY` flags the one recognizer that replaces a
built-in rather than adding a new entity type - see aadhaar_checksum.py.

GSTIN and CREDIT_CARD are deliberately NOT here, even though earlier
versions of this module had custom recognizers for both - Presidio's own
predefined recognizers (`InGstinRecognizer`, `CreditCardRecognizer`)
already cover them, the credit-card one identically-named to what this
project's custom one used to be called. That name collision crashed
`registry.load_predefined_recognizers()` with a bare TypeError, caught
only by an end-to-end smoke test (unit tests of the recognizer in
isolation never exercise the full registry-loading path where the
collision happens - see the project's real cause: Presidio resolves
predefined recognizer classes by a *global name match* across every
currently-loaded EntityRecognizer subclass, not by module path, so any
custom recognizer sharing a class name with a Presidio built-in is a
correctness bug waiting to happen, not just a style nit). Lesson generalized:
before adding a custom recognizer, check presidio_analyzer.predefined_recognizers
for whatever it would be named - don't just check the project instructions'
"still need custom recognizers for" list, which was wrong for GSTIN.
"""

from __future__ import annotations

from presidio_analyzer import PatternRecognizer

from pii_redact.detect.recognizers.aadhaar_checksum import AadhaarChecksumRecognizer
from pii_redact.detect.recognizers.address import AddressRecognizer
from pii_redact.detect.recognizers.ais import AisDownloadIdRecognizer
from pii_redact.detect.recognizers.banking import (
    BankAccountNumberRecognizer,
    DematDpIdRecognizer,
    IfscRecognizer,
    UpiIdRecognizer,
)
from pii_redact.detect.recognizers.dates import DateOfBirthRecognizer
from pii_redact.detect.recognizers.identity_numbers import CinRecognizer, TanRecognizer
from pii_redact.detect.recognizers.kyc_and_scheme_ids import (
    CkycNumberRecognizer,
    EpfUanRecognizer,
    MutualFundFolioRecognizer,
)
from pii_redact.detect.recognizers.other_documents import (
    DrivingLicenseRecognizer,
    ItrAcknowledgementRecognizer,
    RationCardNumberRecognizer,
)

AADHAAR_REPLACEMENT_ENTITY = "IN_AADHAAR"


def get_custom_recognizers() -> list[PatternRecognizer]:
    return [
        AadhaarChecksumRecognizer(),
        AddressRecognizer(),
        AisDownloadIdRecognizer(),
        DateOfBirthRecognizer(),
        TanRecognizer(),
        CinRecognizer(),
        IfscRecognizer(),
        UpiIdRecognizer(),
        BankAccountNumberRecognizer(),
        DematDpIdRecognizer(),
        EpfUanRecognizer(),
        CkycNumberRecognizer(),
        MutualFundFolioRecognizer(),
        DrivingLicenseRecognizer(),
        ItrAcknowledgementRecognizer(),
        RationCardNumberRecognizer(),
    ]
