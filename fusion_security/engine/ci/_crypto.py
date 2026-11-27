"""P0-5: reversible webhook secret storage + runtime decrypt for signing.

Storing only sha256 of the secret is not enough (the signature cannot be replayed).
Use Fernet symmetric encryption with a key derived from FUSION_SECURITY_MASTER_KEY
(PBKDF2-HMAC-SHA256 -> 32B -> base64).
Issue #50 (config-conventions §3): a missing key no longer falls back to a
guessable default literal — dev uses a process-level random seed (old ciphertexts
become undecryptable after restart) plus a loud warning; prod raises RuntimeError
directly (env var name + how to generate it + doc path).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets

logger = logging.getLogger(__name__)

_MASTER_ENV = "FUSION_SECURITY_MASTER_KEY"
_DEV_SEED: str | None = None


def _dev_seed() -> str:
    # Process-level random seed: encrypt/decrypt stay consistent within one process;
    # old ciphertexts become undecryptable after restart — never falls back to a known constant.
    global _DEV_SEED
    if _DEV_SEED is None:
        _DEV_SEED = secrets.token_urlsafe(32)
        logger.warning(
            f"[Crypto] {_MASTER_ENV} not set — dev mode uses a process-level random key;"
            f"existing webhook ciphertexts become undecryptable after restart. Generate and export: "
            f'python -c "import secrets; print(secrets.token_urlsafe(32))";'
            f"see architecture/config-conventions.md"
        )
    return _DEV_SEED


def _derive_fernet_key() -> bytes:
    seed = os.environ.get(_MASTER_ENV, "").strip()
    if not seed:
        if os.getenv("FUSION_PROFILE", "dev") == "prod":
            raise RuntimeError(
                f"{_MASTER_ENV} not set — generate one with: "
                f'python -c "import secrets; print(secrets.token_urlsafe(32))", '
                f"export it before starting the service; see architecture/config-conventions.md"
            )
        seed = _dev_seed()
    digest = hashlib.pbkdf2_hmac("sha256", seed.encode("utf-8"), b"fusion-security-webhook-salt", 100_000, dklen=32)
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    # A missing key in prod raises RuntimeError here and fails fast up the stack,
    # never reaching the silent degradation below.
    key = _derive_fernet_key()
    try:
        from cryptography.fernet import Fernet

        return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] failed to encrypt webhook secret, degrading to empty: {e}")
        return ""


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    key = _derive_fernet_key()
    try:
        from cryptography.fernet import Fernet

        return Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.warning(f"[Crypto] failed to decrypt webhook secret, signature will be skipped: {e}")
        return ""
