"""Custom Presidio anonymizer operator: consistent pseudonymization.

Registered against presidio-anonymizer's OperatorType.Anonymize. Given a
detected entity, looks up (or creates) a stable code from the mapping store
- same real value always yields the same code (e.g. `PERSON_A`, `PAN_A`)
across documents and sessions, per the project instructions.
"""

from __future__ import annotations

from functools import lru_cache

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.operators import Operator, OperatorType

from pii_redact.anonymize.mapping_store import MappingStore, normalize_value


class ConsistentPseudonymOperator(Operator):
    def operate(self, text: str, params: dict | None = None) -> str:
        params = params or {}
        entity_type: str = params["entity_type"]
        mapping_store: MappingStore = params["mapping_store"]
        normalized = normalize_value(entity_type, text)
        return mapping_store.get_or_create_code(entity_type, normalized)

    def validate(self, params: dict | None = None) -> None:
        params = params or {}
        if "mapping_store" not in params:
            raise ValueError("ConsistentPseudonymOperator requires a mapping_store param")

    def operator_name(self) -> str:
        return "consistent_pseudonym"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


@lru_cache(maxsize=1)
def get_anonymizer_engine() -> AnonymizerEngine:
    """Process-wide singleton, same rationale as detect/analyzer.py's
    get_analyzer(): registering the custom operator is cheap but there's no
    reason to redo it per document in a batch run. The built-in "replace"
    operator is always available on any AnonymizerEngine; registering
    ConsistentPseudonymOperator here makes both modes (redact/pseudonymize)
    usable from a single shared engine instance."""
    engine = AnonymizerEngine()
    engine.add_anonymizer(ConsistentPseudonymOperator)
    return engine
