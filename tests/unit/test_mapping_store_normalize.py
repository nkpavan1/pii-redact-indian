from pii_redact.anonymize.mapping_store import normalize_value


def test_person_name_case_and_whitespace_collapse_to_same_key():
    assert normalize_value("PERSON", "Rahul Kumar") == normalize_value(
        "PERSON", "  rahul   kumar  "
    )


def test_person_name_keeps_internal_space():
    assert normalize_value("PERSON", "Rahul Kumar") == "RAHUL KUMAR"


def test_pan_strips_internal_separators():
    assert normalize_value("IN_PAN", "ABCDE 1234F") == normalize_value(
        "IN_PAN", "ABCDE1234F"
    )


def test_pan_is_case_insensitive():
    assert normalize_value("IN_PAN", "abcde1234f") == "ABCDE1234F"
