"""Per-document-type entity allow-lists.

Presidio can detect an entity type without us wanting to act on it in a given
document type - see the "Entity scoping discipline" rule in the project
instructions: DATE_TIME and LOCATION are the known problem cases (DOB must be
redacted, a transaction date must not be). A document type that isn't listed
here falls back to DEFAULT_ALLOWLIST, which is deliberately conservative.

This is config, not code - extend it by adding/editing entries, not by
branching in pipeline logic.
"""

from __future__ import annotations

# Entities considered safe to always act on: they don't collide with
# computation-relevant data in any known document type.
_ALWAYS_SAFE = [
    "IN_PAN",
    "IN_AADHAAR",
    "IN_PASSPORT",
    "IN_VOTER",
    "IN_VEHICLE_REGISTRATION",
    "IN_GSTIN",
    "IFSC",
    "UPI_ID",
    "BANK_ACCOUNT_NUMBER",
    "DRIVING_LICENSE",
    "EPF_UAN",
    "DEMAT_DP_ID",
    "TAN",
    "CIN",
    "ITR_ACK_NUMBER",
    "CKYC_NUMBER",
    "MF_FOLIO_NUMBER",
    "RATION_CARD_NUMBER",
    "CREDIT_CARD",
    "AIS_DOWNLOAD_ID",
    "IN_ADDRESS",
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
]

# Context-scoped variants only - the recognizer itself already requires
# nearby context words (e.g. "date of birth"), so it's safe to always act on
# the entity type it emits without also catching transaction/holding dates.
_DOB_ENTITY = "IN_DATE_OF_BIRTH"

DEFAULT_ALLOWLIST: list[str] = [*_ALWAYS_SAFE, _DOB_ENTITY]

DOC_TYPE_ALLOWLISTS: dict[str, list[str]] = {
    # Form 16 / Form 26AS: has both DOB-adjacent text and assessment-year /
    # payment dates that must survive for the document to remain useful.
    "form16": [*_ALWAYS_SAFE, _DOB_ENTITY],
    # Bank statements: transaction dates and running-balance amounts must
    # never be touched. LOCATION is excluded entirely - branch city names
    # are routinely computation-adjacent (interest rate by branch, etc.) and
    # DATE_TIME (unscoped) is deliberately absent.
    "bank_statement": [*_ALWAYS_SAFE],
    # Demat / capital gains statements: holding-period dates and settlement
    # dates are the whole point of the document - never touch bare DATE_TIME.
    "demat_statement": [*_ALWAYS_SAFE],
    "id_card_scan": [*_ALWAYS_SAFE, _DOB_ENTITY],
    # AIS (Annual Information Statement): has a genuine Date of Birth field
    # for the assessee (same reasoning as form16) AND is dense with
    # quarterly TDS/TCS and SFT transaction/reporting dates that must
    # survive - bare DATE_TIME is deliberately absent, same as every other
    # entry here. AIS_DOWNLOAD_ID (the PAN+date+time ID printed on every
    # AIS/TIS download) is already in _ALWAYS_SAFE, so no extra entry is
    # needed for it specifically.
    "ais": [*_ALWAYS_SAFE, _DOB_ENTITY],
    "generic": DEFAULT_ALLOWLIST,
}


def allowlist_for(doc_type: str | None) -> list[str]:
    if doc_type is None:
        return DEFAULT_ALLOWLIST
    return DOC_TYPE_ALLOWLISTS.get(doc_type, DEFAULT_ALLOWLIST)
