import json
from pathlib import Path

import pytest

from fusion_security.engine.agent.assets import SignatureLibrary, discover_assets, scan_assets
from fusion_security.engine.agent.assets.manifests import parse_mcp_manifest

FIXTURES = Path(__file__).parent / "fixtures" / "agent-assets"

EXPECTED_RULES = {
    "AGT-DESC-POISONING",
    "AGT-PERM-ENV",
    "AGT-AUTO-APPROVE",
    "AGT-SIGNATURE-MATCH",
    "AGT-PERM-FS-WIDE",
    "AGT-UNPINNED-DEP",
    "AGT-CMD-RISK",
}


class TestManifestParsers:
    def test_discover_finds_all_four_assets(self):
        inv = discover_assets(FIXTURES)
        assert inv.files_scanned == 4
        assert len(inv.mcp_servers) == 2
        assert len(inv.skills) == 2

    def test_mcp_manifest_parses_full_shape(self, tmp_path):
        f = tmp_path / "mcp.json"
        f.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "srv": {
                            "command": "npx",
                            "args": ["-y", "pkg@1.0.0"],
                            "env": {"TOKEN": "x"},
                            "autoApprove": ["t1"],
                            "url": "https://example.local/sse",
                            "tools": [{"name": "t1", "description": "does a thing"}],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        servers = parse_mcp_manifest(f, "mcp.json")
        assert len(servers) == 1
        s = servers[0]
        assert s.name == "srv" and s.command == "npx" and s.env == {"TOKEN": "x"}
        assert s.auto_approve == ["t1"] and s.tools[0]["name"] == "t1"

    def test_unparsable_manifest_yields_zero_entries(self, tmp_path):
        f = tmp_path / "mcp.json"
        f.write_text("{not json", encoding="utf-8")
        assert parse_mcp_manifest(f, "mcp.json") == []


class TestFixtureScan:
    """Plan gate: 1 poisoned MCP + 1 over-privileged skill + 2 benign,
    every expected rule fires on the bad assets, zero findings on benign."""

    @pytest.fixture(scope="class")
    def findings(self):
        inv, findings = scan_assets(FIXTURES)
        return findings

    def test_all_expected_rules_fire(self, findings):
        rules = {f.rule_id for f in findings}
        assert rules >= EXPECTED_RULES, f"missing: {EXPECTED_RULES - rules}"

    def test_zero_false_positives_on_benign_project(self, findings):
        benign_hits = [f for f in findings if f.file_path.startswith("project-c")]
        assert not benign_hits, f"false positives on benign assets: {[f.rule_id for f in benign_hits]}"

    def test_poisoned_and_privileged_assets_flagged(self, findings):
        assert any(f.rule_id == "AGT-DESC-POISONING" and f.file_path.startswith("project-a") for f in findings)
        assert any(f.file_path.startswith("project-b") for f in findings)

    def test_findings_carry_cwe_and_snippet(self, findings):
        f = findings[0]
        assert f.cwe_id and f.code_snippet and f.rule_id.startswith("AGT-")


class TestSignatureLibrary:
    def test_bundled_library_loads(self):
        lib = SignatureLibrary.load()
        assert lib.package_indicators and lib.domain_indicators and lib.command_indicators
        assert lib.source.endswith("signatures.json")

    def test_override_bundle_replaces_bundled(self, tmp_path):
        bundle = tmp_path / "sigs.json"
        bundle.write_text(
            json.dumps(
                {
                    "version": 2,
                    "package_indicators": ["totally-evil-pkg"],
                    "domain_indicators": [],
                    "command_indicators": [],
                }
            ),
            encoding="utf-8",
        )
        lib = SignatureLibrary.load(bundle)
        assert lib.version == 2
        assert lib.match_package("install totally-evil-pkg now") == ["totally-evil-pkg"]
        assert not lib.domain_indicators

    def test_env_override(self, tmp_path, monkeypatch):
        bundle = tmp_path / "sigs.json"
        bundle.write_text(json.dumps({"version": 3, "domain_indicators": ["bad.example"]}), encoding="utf-8")
        monkeypatch.setenv("FUSION_AGENT_SIGNATURES", str(bundle))
        assert SignatureLibrary.load().match_domain("https://bad.example/x") == ["bad.example"]

    def test_unreadable_bundle_degrades_to_empty(self, tmp_path):
        lib = SignatureLibrary.load(tmp_path / "missing.json")
        assert not lib.package_indicators


class TestAssetVulnerabilityFlow:
    def test_findings_reuse_vulnerability_model(self):
        inv, findings = scan_assets(FIXTURES)
        for f in findings:
            assert f.id.startswith("V-")
            assert f.severity in {"critical", "high", "medium", "low"}
            assert f.fix_suggestion

    def test_api_asset_scan_endpoint(self):
        from fastapi.testclient import TestClient

        from fusion_security.api.app import create_app
        from fusion_security.api.auth import auth_manager
        from fusion_security.db.session import init_db

        init_db(":memory:")
        app = create_app()
        client = TestClient(app)
        raw = auth_manager.create_api_key("assets-test", ["admin"], tenant_id="default")
        resp = client.post(
            "/api/v1/agent/asset-scan",
            headers={"X-API-Key": raw, "X-Tenant-Id": "default"},
            json={"path": str(FIXTURES)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mcp_servers"] == 2 and data["skills"] == 2
        assert {f["rule_id"] for f in data["findings"]} >= EXPECTED_RULES

    def test_api_asset_scan_404_on_missing_path(self):
        from fastapi.testclient import TestClient

        from fusion_security.api.app import create_app
        from fusion_security.api.auth import auth_manager
        from fusion_security.db.session import init_db

        init_db(":memory:")
        app = create_app()
        client = TestClient(app)
        raw = auth_manager.create_api_key("assets-test-404", ["admin"], tenant_id="default")
        resp = client.post(
            "/api/v1/agent/asset-scan",
            headers={"X-API-Key": raw, "X-Tenant-Id": "default"},
            json={"path": "/tmp/definitely-not-here-9999"},
        )
        assert resp.status_code == 404
