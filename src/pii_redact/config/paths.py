"""Default locations for the Phase 7 tools (redact-key, redact-publish,
redact-service).

Everything those tools own lives under one directory: the mapping store,
the audit log, the publish manifest and review reports. That directory must
never be inside a vault or mounted into a container. It defaults to
H:\\ai\\redaction and can be moved with the PII_REDACT_HOME environment
variable or each tool's own flags.

The mapping store's key is bound to the store's resolved path (see
anonymize/mapping_store.py), so once a store exists, never move it.

The legacy `redact` command keeps its own defaults (~/.pii_redact/).
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "PII_REDACT_HOME"
DEFAULT_HOME = Path(r"H:\ai\redaction")

STORE_FILE_NAME = "mapping_store.enc"
AUDIT_LOG_FILE_NAME = "audit.log.jsonl"


def redaction_home() -> Path:
    configured = os.environ.get(HOME_ENV)
    return Path(configured) if configured else DEFAULT_HOME


def default_store_path() -> Path:
    return redaction_home() / STORE_FILE_NAME


def default_audit_log_path() -> Path:
    return redaction_home() / AUDIT_LOG_FILE_NAME
