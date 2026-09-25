from pii_redact.config.allowlists import DEFAULT_ALLOWLIST, DOC_TYPE_ALLOWLISTS, allowlist_for
from pii_redact.detect.analyzer import get_analyzer


def test_every_allowlisted_entity_has_a_recognizer():
    # Presidio silently skips an entity type it has no recognizer for, so a
    # typo here would quietly switch redaction off for that type.
    supported = set(get_analyzer().get_supported_entities())
    for doc_type, entities in DOC_TYPE_ALLOWLISTS.items():
        assert set(entities) <= supported, doc_type


def test_chat_allowlist_is_generic_plus_context_free_mobiles():
    assert allowlist_for("chat") == [*allowlist_for("generic"), "IN_MOBILE"]


def test_documents_never_get_the_context_free_mobile_recognizer():
    for doc_type, entities in DOC_TYPE_ALLOWLISTS.items():
        if doc_type != "chat":
            assert "IN_MOBILE" not in entities, doc_type


def test_unknown_doc_type_falls_back_to_default():
    assert allowlist_for("some_unregistered_type") == DEFAULT_ALLOWLIST


def test_none_doc_type_falls_back_to_default():
    assert allowlist_for(None) == DEFAULT_ALLOWLIST


def test_bank_statement_excludes_unscoped_date_time():
    # DATE_TIME must never appear bare - transaction dates must survive.
    assert "DATE_TIME" not in allowlist_for("bank_statement")


def test_bank_statement_excludes_location():
    assert "LOCATION" not in allowlist_for("bank_statement")


def test_all_doc_types_include_core_identity_numbers():
    for doc_type in ("form16", "bank_statement", "demat_statement", "id_card_scan", "ais", "generic"):
        entities = allowlist_for(doc_type)
        assert "IN_PAN" in entities
        assert "IN_AADHAAR" in entities


def test_dob_entity_included_where_expected():
    for doc_type in ("form16", "id_card_scan", "ais", "generic"):
        assert "IN_DATE_OF_BIRTH" in allowlist_for(doc_type)


def test_ais_includes_download_id_and_excludes_bare_date_time():
    entities = allowlist_for("ais")
    assert "AIS_DOWNLOAD_ID" in entities
    assert "DATE_TIME" not in entities
    assert "LOCATION" not in entities


def test_bank_statement_excludes_dob_entity():
    # A bank statement's date-scoping risk is high enough that even the
    # context-scoped DOB entity is deliberately left out - see the
    # comment in config/allowlists.py.
    assert "IN_DATE_OF_BIRTH" not in allowlist_for("bank_statement")
