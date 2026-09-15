from pathlib import Path

from presidio_analyzer import RecognizerResult
from presidio_anonymizer.entities import OperatorConfig

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.anonymize.operators import ConsistentPseudonymOperator, get_anonymizer_engine


class InMemoryMappingStore(MappingStore):
    """Minimal working MappingStore for tests - the real one's persistence
    is still NotImplementedError (see anonymize/mapping_store.py)."""

    def __init__(self):
        super().__init__(store_path=Path("unused"))
        self._value_to_code: dict[tuple[str, str], str] = {}
        self._code_to_value: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def get_or_create_code(self, entity_type: str, raw_value: str) -> str:
        key = (entity_type, raw_value)
        if key in self._value_to_code:
            return self._value_to_code[key]
        self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
        letter = chr(ord("A") + self._counters[entity_type] - 1)
        code = f"{entity_type}_{letter}"
        self._value_to_code[key] = code
        self._code_to_value[code] = raw_value
        return code

    def reverse_lookup(self, code: str) -> str | None:
        return self._code_to_value.get(code)

    def all_codes(self) -> dict[str, str]:
        return dict(self._code_to_value)


def test_get_anonymizer_engine_is_a_singleton():
    assert get_anonymizer_engine() is get_anonymizer_engine()


def test_consistent_pseudonym_operator_via_engine_gives_stable_codes():
    engine = get_anonymizer_engine()
    store = InMemoryMappingStore()
    operators = {
        "DEFAULT": OperatorConfig("consistent_pseudonym", {"mapping_store": store})
    }

    text1 = "Contact: Rahul Kumar"
    result1 = engine.anonymize(
        text=text1,
        analyzer_results=[RecognizerResult(entity_type="PERSON", start=9, end=20, score=0.85)],
        operators=operators,
    )

    text2 = "Signed by Rahul Kumar"
    result2 = engine.anonymize(
        text=text2,
        analyzer_results=[RecognizerResult(entity_type="PERSON", start=10, end=21, score=0.85)],
        operators=operators,
    )

    code1 = result1.text.replace("Contact: ", "")
    code2 = result2.text.replace("Signed by ", "")
    assert code1 == code2  # same real value -> same code, even across separate calls
    assert store.reverse_lookup(code1) == "RAHUL KUMAR"  # normalized per mapping_store rules


def test_consistent_pseudonym_operator_gives_different_codes_for_different_values():
    engine = get_anonymizer_engine()
    store = InMemoryMappingStore()
    operators = {
        "DEFAULT": OperatorConfig("consistent_pseudonym", {"mapping_store": store})
    }

    r1 = engine.anonymize(
        text="Rahul Kumar",
        analyzer_results=[RecognizerResult(entity_type="PERSON", start=0, end=11, score=0.85)],
        operators=operators,
    )
    r2 = engine.anonymize(
        text="Priya Singh",
        analyzer_results=[RecognizerResult(entity_type="PERSON", start=0, end=11, score=0.85)],
        operators=operators,
    )
    assert r1.text != r2.text


def test_consistent_pseudonym_operator_validate_requires_mapping_store():
    op = ConsistentPseudonymOperator()
    try:
        op.validate({})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for missing mapping_store")
