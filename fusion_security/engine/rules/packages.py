"""Signed rule packages (evolution plan P3.1).

Versioned bundle format: a single .frpkg JSON file carrying metadata,
rules, a canonical digest and an Ed25519 signature. Key pair is generated
offline (`rules-package keygen`); verification happens at install time
against the publisher public key. Tampered or unsigned packages are
rejected with a clear audit event. Custom rules migrate from DB-only to
packages; the DB stays the storage backend after verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

logger = logging.getLogger(__name__)

PACKAGE_FORMAT = "fusion-rule-package"
PACKAGE_VERSION = 1


class PackageError(Exception):
    pass


@dataclass
class RulePackage:
    metadata: dict
    rules: list[dict]
    digest: str
    signature: str
    path: str = ""


def generate_key_pair(private_key_path: Path, overwrite: bool = False) -> Path:
    if private_key_path.exists() and not overwrite:
        raise PackageError(f"refusing to overwrite existing key: {private_key_path}")
    key = Ed25519PrivateKey.generate()
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub = private_key_path.with_suffix(private_key_path.suffix + ".pub")
    pub.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    logger.info(f"[Packages] key pair generated: {private_key_path} + {pub}")
    return private_key_path


def _canonical(payload: dict) -> bytes:
    # Canonical form excludes digest/signature so the signature covers
    # metadata + rules only.
    core = {k: v for k, v in payload.items() if k not in {"digest", "signature"}}
    return json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def build_package(metadata: dict, rules: list[dict], out_path: Path, private_key_path: Path) -> RulePackage:
    payload = {
        "format": PACKAGE_FORMAT,
        "version": PACKAGE_VERSION,
        "metadata": metadata,
        "rules": rules,
    }
    core = _canonical(payload)
    payload["digest"] = hashlib.sha256(core).hexdigest()
    try:
        key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    except Exception as e:
        raise PackageError(f"unreadable private key {private_key_path}: {e}") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise PackageError(f"key {private_key_path} is not an Ed25519 private key")
    payload["signature"] = key.sign(core).hex()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"[Packages] built {out_path}: {len(rules)} rules, digest={payload['digest'][:12]}…")
    return RulePackage(
        metadata=metadata, rules=rules, digest=payload["digest"], signature=payload["signature"], path=str(out_path)
    )


def load_package(path: Path) -> RulePackage:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise PackageError(f"unreadable package {path}: {e}") from e
    if payload.get("format") != PACKAGE_FORMAT:
        raise PackageError(f"not a {PACKAGE_FORMAT} bundle: {path}")
    if int(payload.get("version", 0)) != PACKAGE_VERSION:
        raise PackageError(f"unsupported package version: {payload.get('version')}")
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    if digest != payload.get("digest"):
        raise PackageError("package digest mismatch — content does not match declared digest")
    try:
        signature = bytes.fromhex(str(payload.get("signature", "")))
    except ValueError as e:
        raise PackageError("signature is not valid hex") from e
    return RulePackage(
        metadata=payload.get("metadata", {}),
        rules=payload.get("rules", []),
        digest=digest,
        signature=signature.hex(),
        path=str(path),
    )


def verify_package(pkg: RulePackage, public_key_path: Path) -> None:
    try:
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except Exception as e:
        raise PackageError(f"unreadable public key {public_key_path}: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise PackageError(f"key {public_key_path} is not an Ed25519 public key")
    # Re-canonicalize from the on-disk payload to guarantee the verified
    # bytes equal the digest the package declares.
    payload = json.loads(Path(pkg.path).read_text(encoding="utf-8"))
    core = _canonical(payload)
    if hashlib.sha256(core).hexdigest() != pkg.digest:
        raise PackageError("package digest mismatch — tampered after load")
    try:
        key.verify(bytes.fromhex(pkg.signature), core)
    except InvalidSignature as e:
        raise PackageError("signature verification failed — package is tampered or signed by another key") from e
    logger.info(f"[Packages] verified {pkg.path} (digest={pkg.digest[:12]}…, rules={len(pkg.rules)})")


_REQUIRED_RULE_FIELDS = {"id", "name", "severity", "pattern"}


def install_rules(pkg: RulePackage, public_key_path: Path) -> list[str]:
    """Verify then upsert package rules into the DB (source='package').

    Raises PackageError on any verification failure — callers should log
    the rejection to the audit stream.
    """
    verify_package(pkg, public_key_path)
    for rule in pkg.rules:
        missing = _REQUIRED_RULE_FIELDS - set(rule)
        if missing:
            raise PackageError(f"rule missing required fields {sorted(missing)}: {rule.get('id', '?')}")
    from ...db.models import RuleORM
    from ...db.session import get_session

    installed: list[str] = []
    with get_session() as session:
        for rule in pkg.rules:
            row = session.get(RuleORM, str(rule["id"]))
            if row is None:
                row = RuleORM(id=str(rule["id"]))
                session.add(row)
            row.name = str(rule.get("name", ""))[:200]
            row.description = str(rule.get("description", ""))
            row.severity = str(rule.get("severity", "medium"))[:10]
            row.pattern = str(rule.get("pattern", ""))
            row.language = str(rule.get("language", "all"))[:20]
            row.cwe_id = str(rule.get("cwe_id", ""))[:20]
            row.category = str(rule.get("category", "injection"))[:50]
            row.detection_type = str(rule.get("detection_type", "regex"))[:20]
            row.enabled = bool(rule.get("enabled", True))
            row.source = "package"
            installed.append(str(rule["id"]))
        session.commit()
    logger.info(f"[Packages] installed {len(installed)} rules from {pkg.path}: {installed[:5]}")
    return installed
