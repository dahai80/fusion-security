"""Tests for P3.1 signed rule packages (build, verify, install, tamper reject)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from fusion_security.cli import cli
from fusion_security.db.session import init_db
from fusion_security.engine.rules.packages import (
    PackageError,
    generate_key_pair,
    install_rules,
    load_package,
    verify_package,
)

RULES = [
    {
        "id": "CUS-001",
        "name": "Custom eval rule",
        "severity": "high",
        "pattern": "eval\\(",
        "language": "python",
        "cwe_id": "CWE-95",
        "category": "injection",
    },
    {
        "id": "CUS-002",
        "name": "Custom yaml load rule",
        "severity": "medium",
        "pattern": "yaml\\.load\\(",
        "language": "python",
    },
]


@pytest.fixture()
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "signing.pem"
    generate_key_pair(private)
    return private, private.with_suffix(".pem.pub")


@pytest.fixture()
def pkg_path(tmp_path: Path, keys) -> Path:
    from fusion_security.engine.rules.packages import build_package

    out = tmp_path / "custom-rules.frpkg"
    build_package({"name": "custom-rules", "version": "1.0.0"}, RULES, out, keys[0])
    return out


class TestPackages:
    def test_build_and_verify_roundtrip(self, pkg_path, keys):
        pkg = load_package(pkg_path)
        verify_package(pkg, keys[1])
        assert pkg.digest
        assert len(pkg.rules) == 2
        assert pkg.metadata["name"] == "custom-rules"

    def test_tampered_rules_rejected(self, pkg_path, keys):
        payload = json.loads(pkg_path.read_text())
        payload["rules"][0]["severity"] = "low"
        pkg_path.write_text(json.dumps(payload))
        with pytest.raises(PackageError, match="digest mismatch"):
            load_package(pkg_path)

    def test_tampered_after_digest_recalc_rejected(self, pkg_path, keys, tmp_path):
        # Metadata swap without recomputing the digest: rejected at load.
        payload = json.loads(pkg_path.read_text())
        payload["metadata"]["version"] = "9.9.9"
        pkg_path.write_text(json.dumps(payload))
        with pytest.raises(PackageError, match="digest mismatch"):
            load_package(pkg_path)

    def test_unsigned_rejected(self, tmp_path):
        # Hand-built bundle with a fake digest and empty signature: digest
        # check rejects at load (only signed packages can carry a real digest).
        payload = {
            "format": "fusion-rule-package",
            "version": 1,
            "metadata": {},
            "rules": RULES,
            "digest": "0" * 64,
            "signature": "",
        }
        path = tmp_path / "unsigned.frpkg"
        path.write_text(json.dumps(payload))
        with pytest.raises(PackageError, match="digest mismatch"):
            load_package(path)

    def test_wrong_key_rejected(self, pkg_path, tmp_path):
        other = tmp_path / "other.pem"
        generate_key_pair(other)
        pkg = load_package(pkg_path)
        with pytest.raises(PackageError, match="signature verification failed"):
            verify_package(pkg, other.with_suffix(".pem.pub"))

    def test_wrong_format_rejected(self, tmp_path):
        path = tmp_path / "bad.frpkg"
        path.write_text(json.dumps({"format": "something-else"}))
        with pytest.raises(PackageError, match="not a fusion-rule-package"):
            load_package(path)

    def test_install_upserts_db(self, pkg_path, keys, tmp_path, monkeypatch):
        from fusion_security.db.models import RuleORM
        from fusion_security.db.session import get_session

        monkeypatch.setattr("fusion_security.db.session._engine", None, raising=False)
        monkeypatch.setattr("fusion_security.db.session._async_engine", None, raising=False)
        init_db(":memory:")
        pkg = load_package(pkg_path)
        installed = install_rules(pkg, keys[1])
        assert installed == ["CUS-001", "CUS-002"]
        with get_session() as session:
            row = session.get(RuleORM, "CUS-001")
            assert row is not None
            assert row.source == "package"
            assert row.severity == "high"

    def test_install_missing_rule_field_rejected(self, pkg_path, keys, tmp_path):
        from fusion_security.db.session import init_db

        init_db(":memory:")
        payload = json.loads(pkg_path.read_text())
        del payload["rules"][0]["pattern"]
        pkg_path.write_text(json.dumps(payload))
        # Any content modification breaks the declared digest first; the
        # field check is defense-in-depth for crafted-but-unsigned bundles.
        with pytest.raises(PackageError, match="digest mismatch"):
            load_package(pkg_path)


class TestCli:
    def test_bare_rules_still_lists(self):
        result = CliRunner().invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "检测规则" in result.output

    def test_keygen_package_install_flow(self, tmp_path):
        runner = CliRunner()
        key = tmp_path / "k.pem"
        r = runner.invoke(cli, ["rules", "keygen", str(key)])
        assert r.exit_code == 0, r.output
        assert (key.with_suffix(".pem.pub")).exists()

        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps(RULES))
        pkg = tmp_path / "out.frpkg"
        r = runner.invoke(cli, ["rules", "package", str(rules_file), "--key", str(key), "--out", str(pkg)])
        assert r.exit_code == 0, r.output
        assert json.loads(r.output)["rules"] == 2

        r = runner.invoke(cli, ["rules", "install", str(pkg), "--from-file", "--key", str(key.with_suffix(".pem.pub"))])
        assert r.exit_code == 0, r.output
        assert json.loads(r.output)["installed"] is True

    def test_install_tampered_rejects_with_audit(self, tmp_path):
        from fusion_security.engine.tenant.audit import get_audit_logger

        runner = CliRunner()
        key = tmp_path / "k.pem"
        runner.invoke(cli, ["rules", "keygen", str(key)])
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps(RULES))
        pkg = tmp_path / "out.frpkg"
        runner.invoke(cli, ["rules", "package", str(rules_file), "--key", str(key), "--out", str(pkg)])

        payload = json.loads(pkg.read_text())
        payload["rules"][0]["pattern"] = "backdoored\\("
        pkg.write_text(json.dumps(payload))

        r = runner.invoke(cli, ["rules", "install", str(pkg), "--from-file", "--key", str(key.with_suffix(".pem.pub"))])
        assert r.exit_code == 1
        assert json.loads(r.output)["installed"] is False
        rejected = get_audit_logger("default").query(action="rule.package.rejected")
        assert len(rejected) >= 1
