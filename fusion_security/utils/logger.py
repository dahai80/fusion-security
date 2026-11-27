"""Fusion-Security logging utilities."""

from __future__ import annotations

import logging
import re
import sys

logger = logging.getLogger(__name__)

# Common secret-bearing key names: password / secret / token / api_key / authorization / credential / private_key, etc.
_SECRET_KEY = (
    r"(?i)(password|passwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|refresh[_-]?token|auth[_-]?token|"
    r"authorization|credential|bearer)\s*[:=]\s*"
)
# Key-value pairs: key followed by a quoted or bare value. On match only the key and separator are kept; the value becomes [REDACTED].
_KV_PATTERN = re.compile(_SECRET_KEY + r"[\"']?[A-Za-z0-9_\-\.:/+=~$&%#@!]+")
# Bearer headers: Authorization: Bearer xxx or a bare Bearer xxx.
_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=:/+]+")
# Long hex/Base64 strings (>=32 chars, often API tokens / JWTs / sha256) are only safe to redact near a secret context.
# Standalone long strings are frequently benign (file hashes, commit shas), so they are not matched globally; KV/Bearer patterns cover them.
_REDACTED = "[REDACTED]"


class SecretRedactingFilter(logging.Filter):
    """Logging filter: redacts secret-bearing key-value pairs and Bearer tokens to keep credentials out of stdout/log files."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception as e:
            logger.debug(f"failed to read message for redaction, passing through unchanged: {e}")
            return True
        # Redact Bearer tokens first (so the KV pattern does not consume the "Bearer" word and leave the token behind), then key-value pairs.
        redacted = _BEARER_PATTERN.sub("Bearer " + _REDACTED, msg)
        redacted = _KV_PATTERN.sub(_REDACTED, redacted)
        if redacted != msg:
            # Message is fully formatted; pin msg and clear args to avoid errors from a second % interpolation.
            record.msg = redacted
            record.args = None
        return True


def setup_logger(name: str = "fusion_security", level: int = logging.INFO, verbose: bool = False):
    root_logger = logging.getLogger(name)
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    fmt = "[%(asctime)s] %(levelname)-8s %(message)s" if verbose else "%(levelname)-8s %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    handler.addFilter(SecretRedactingFilter())
    root_logger.addHandler(handler)
    return root_logger
