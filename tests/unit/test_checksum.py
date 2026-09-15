from pii_redact.detect.checksum import verhoeff_is_valid


def test_verhoeff_known_valid():
    # Classic Wikipedia Verhoeff worked example: "236" with check digit "3".
    assert verhoeff_is_valid("2363") is True


def test_verhoeff_known_invalid():
    assert verhoeff_is_valid("2364") is False


def test_verhoeff_rejects_non_digit():
    assert verhoeff_is_valid("12a4") is False
