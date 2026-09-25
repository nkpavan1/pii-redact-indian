"""Field names as context for structured data: CSV/XLSX/JSON values are
analyzed as "<label>: <value>", so a header like "Account No" counts as
context. Synthetic bank statements only."""

import json

import openpyxl
import pytest

from pii_redact.detect.analyzer import detect_in_block
from pii_redact.detect.field_context import field_labels, label_words, looks_like_a_label
from pii_redact.pipeline import analyze_document
from pii_redact.types import Location, TextBlock

ACCOUNT = "123456789012"
BANK = ["BANK_ACCOUNT_NUMBER", "PERSON", "IN_PAN", "RATION_CARD_NUMBER", "ITR_ACK_NUMBER", "MF_FOLIO_NUMBER"]


def _detected_texts(path, doc_type="bank_statement"):
    extracted, detections = analyze_document(path, doc_type)
    return {(d.entity_type, extracted.blocks[d.block_index].text[d.start : d.end]) for d in detections}


def _values(found):
    return {text for _, text in found}


def test_an_account_number_alone_is_not_detected_without_its_label():
    # The baseline this step fixes: no context, no detection.
    assert detect_in_block(TextBlock(ACCOUNT, Location(row=0, column="x")), 0, BANK) == []


# --- label words


@pytest.mark.parametrize(
    "name, words",
    [
        ("account_number", "account number"),
        ("accountNumber", "account Number"),
        ("A/C No", "account No"),
        ("a/c no.", "account no"),
        ("Acct-No", "account No"),
        ("Customer Id", "Customer Id"),
    ],
)
def test_field_names_become_context_words(name, words):
    assert label_words(name) == words


@pytest.mark.parametrize("text, expected", [("Account No", True), ("Narration", True), ("50000.00", False),
                                            ("01/03/2026", False), (ACCOUNT, False), ("", False)])
def test_only_label_like_cells_are_used_as_labels(text, expected):
    assert looks_like_a_label(text) is expected


# --- CSV


def test_csv_account_number_under_its_header_is_detected(tmp_path):
    path = tmp_path / "statement.csv"
    path.write_bytes(
        b"Date,Narration,Chq/Ref No,Account No,Withdrawal Amt,Deposit Amt,Closing Balance\n"
        b"01/03/2026,NEFT CR SALARY,000000123456,123456789012,,50000.00,152000.00\n"
        b"03/03/2026,UPI DR GROCERY,512345678901,123456789012,1200.00,,150800.00\n"
    )
    found = _detected_texts(path)
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in found
    # Nothing else in the statement is touched: dates, amounts, references,
    # narrations, and the headers themselves.
    assert _values(found) == {ACCOUNT}


def test_csv_abbreviated_header_a_c_no_counts_as_account(tmp_path):
    path = tmp_path / "statement.csv"
    path.write_bytes(b"Date,A/C No,Amount\n01/03/2026,123456789012,500.00\n02/03/2026,123456789012,700.00\n")
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in _detected_texts(path)


def test_csv_label_beside_value_layout(tmp_path):
    path = tmp_path / "summary.csv"
    path.write_bytes(b"Field,Value\nAccount No,123456789012\nBranch,Andheri East\n")
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in _detected_texts(path)


# --- XLSX


def _workbook(path, rows):
    wb = openpyxl.Workbook()
    for row in rows:
        wb.active.append(row)
    wb.save(path)
    return path


def test_xlsx_account_number_under_its_header_is_detected(tmp_path):
    path = _workbook(tmp_path / "statement.xlsx", [
        ["Date", "Narration", "Account No", "Amount"],
        ["01/03/2026", "NEFT CR SALARY", ACCOUNT, "50000.00"],
        ["02/03/2026", "UPI DR GROCERY", ACCOUNT, "1200.00"],
    ])
    found = _detected_texts(path)
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in found
    assert _values(found) == {ACCOUNT}


def test_xlsx_header_below_a_preamble_is_found(tmp_path):
    path = _workbook(tmp_path / "statement.xlsx", [
        ["Synthetic Bank Ltd"],
        ["Statement of account"],
        [],
        ["Date", "Narration", "Amount", "Account Number"],
        ["01/03/2026", "NEFT CR SALARY", "50000.00", "987654321098"],
        ["02/03/2026", "UPI DR GROCERY", "1200.00", "987654321098"],
    ])
    assert ("BANK_ACCOUNT_NUMBER", "987654321098") in _detected_texts(path)


def test_xlsx_label_to_the_left_is_used(tmp_path):
    path = _workbook(tmp_path / "summary.xlsx", [["Account No", ACCOUNT], ["Amount", "50000.00"]])
    found = _detected_texts(path)
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in found
    assert "50000.00" not in _values(found)


def test_xlsx_labels_never_come_from_values(tmp_path):
    path = _workbook(tmp_path / "t.xlsx", [["Account No"], [ACCOUNT], ["55555555555"]])
    extracted, _ = analyze_document(path, "bank_statement")
    labels = field_labels(extracted)
    # Both numbers get the header as their label; the first number is not
    # the second one's label.
    assert sorted(labels.values()) == ["Account No", "Account No"]


# --- JSON


def test_json_keys_are_context_including_camel_case_and_arrays(tmp_path):
    path = tmp_path / "customer.json"
    path.write_text(json.dumps({"customer": {
        "accountNumber": ACCOUNT,
        "linked_accounts": ["223456789012"],
        "amount": "1500",
        "reference": "512345678901",
    }}), encoding="utf-8")
    found = _detected_texts(path)
    assert ("BANK_ACCOUNT_NUMBER", ACCOUNT) in found
    assert ("BANK_ACCOUNT_NUMBER", "223456789012") in found
    assert _values(found) == {ACCOUNT, "223456789012"}


# --- context only adds, and the ration-card fix


def test_a_label_never_hides_what_the_value_alone_shows(tmp_path):
    path = tmp_path / "t.csv"
    path.write_bytes(b"Remarks,Amount\nABCPE1234F,500\nsecond row,700\n")
    assert ("IN_PAN", "ABCPE1234F") in _detected_texts(path)


@pytest.mark.parametrize("text", ["Narration", "Registration", "Cardholder"])
def test_words_containing_ration_or_card_are_not_ration_card_numbers(text):
    block = TextBlock(text, Location(row=-1, column="col_0"))
    assert detect_in_block(block, 0, ["RATION_CARD_NUMBER"]) == []


def test_a_real_ration_card_number_is_still_detected():
    block = TextBlock("ration card RC12345678", Location())
    found = detect_in_block(block, 0, ["RATION_CARD_NUMBER"])
    assert [block.text[d.start : d.end] for d in found] == ["RC12345678"]
