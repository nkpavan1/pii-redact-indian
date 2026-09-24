import os
import sys
from pathlib import Path

import keyring
import pytest

# Allow running the test suite against the source tree directly, without
# requiring `pip install -e .` first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# The real mapping store keeps its encryption key in the OS credential store
# (Windows Credential Manager). The suite must never read or write it by
# accident: every test that needs a MappingStore passes an explicit key, and
# the one test that deliberately exercises the keyring path is marked
# `keyring` and only runs when this env var is set.
_KEYRING_OPT_IN_ENV = "PII_REDACT_KEYRING_TESTS"


def _keyring_opted_in() -> bool:
    return os.environ.get(_KEYRING_OPT_IN_ENV) == "1"


def pytest_collection_modifyitems(config, items):
    if _keyring_opted_in():
        return
    skip = pytest.mark.skip(
        reason=f"touches the OS credential store; set {_KEYRING_OPT_IN_ENV}=1 to run"
    )
    for item in items:
        if "keyring" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _block_os_credential_store(request, monkeypatch):
    """Fails any test that reaches the OS credential store without opting in,
    instead of silently creating a real Credential Manager entry."""
    if "keyring" in request.keywords and _keyring_opted_in():
        return

    def _refuse(*_args, **_kwargs):
        raise RuntimeError(
            "test tried to access the OS credential store - pass an explicit "
            "key to MappingStore, or mark the test `keyring`"
        )

    for name in ("get_password", "set_password", "delete_password", "get_credential"):
        monkeypatch.setattr(keyring, name, _refuse)
