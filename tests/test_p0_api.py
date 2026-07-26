from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fusion_security.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


# ===== Patches API =====

class TestPatchesAPI:

    def test_list_patches_empty(self, client):
        resp = client.get("/api/v1/patches")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_patch_not_found(self, client):
        resp = client.get("/api/v1/patches/nonexistent")
        assert resp.status_code == 404

    def test_update_patch_not_found(self, client):
        resp = client.patch("/api/v1/patches/nonexistent", json={"status": "applied"})
        assert resp.status_code == 404

    def test_apply_patch_not_found(self, client):
        resp = client.post("/api/v1/patches/nonexistent/apply")
        assert resp.status_code == 404

    def test_generate_patch_vuln_not_found(self, client):
        resp = client.post("/api/v1/patches/generate/nonexistent")
        assert resp.status_code == 404


# ===== Reports API =====

class TestReportsAPI:

    def test_generate_report_scan_not_found(self, client):
        body = {"scan_id": "nonexistent", "format": "md"}
        resp = client.post("/api/v1/reports/generate", json=body)
        assert resp.status_code == 404

    def test_generate_report_json_format(self, client):
        body = {"scan_id": "nonexistent", "format": "json"}
        resp = client.post("/api/v1/reports/generate", json=body)
        assert resp.status_code == 404

    def test_generate_report_html_format(self, client):
        body = {"scan_id": "nonexistent", "format": "html"}
        resp = client.post("/api/v1/reports/generate", json=body)
        assert resp.status_code == 404


# ===== Webhooks API =====

class TestWebhooksAPI:

    def test_create_webhook(self, client):
        resp = client.post("/api/v1/integrations/webhooks", params={
            "url": "https://example.com/hook",
            "events": ["scan.completed"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["url"] == "https://example.com/hook"
        assert "id" in data

    def test_list_webhooks(self, client):
        client.post("/api/v1/integrations/webhooks", params={"url": "https://example.com/hook2"})
        resp = client.get("/api/v1/integrations/webhooks")
        assert resp.status_code == 200
        assert "webhooks" in resp.json()

    def test_get_webhook(self, client):
        create_resp = client.post("/api/v1/integrations/webhooks", params={"url": "https://example.com/hook3"})
        wid = create_resp.json()["id"]
        resp = client.get(f"/api/v1/integrations/webhooks/{wid}")
        assert resp.status_code == 200
        assert resp.json()["url"] == "https://example.com/hook3"

    def test_get_webhook_not_found(self, client):
        resp = client.get("/api/v1/integrations/webhooks/xxx")
        assert resp.status_code == 404

    def test_update_webhook(self, client):
        create_resp = client.post("/api/v1/integrations/webhooks", params={"url": "https://example.com/hook4"})
        wid = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/integrations/webhooks/{wid}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_delete_webhook(self, client):
        create_resp = client.post("/api/v1/integrations/webhooks", params={"url": "https://example.com/hook5"})
        wid = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/integrations/webhooks/{wid}")
        assert resp.status_code == 200
        resp2 = client.get(f"/api/v1/integrations/webhooks/{wid}")
        assert resp2.status_code == 404

    def test_delete_webhook_not_found(self, client):
        resp = client.delete("/api/v1/integrations/webhooks/xxx")
        assert resp.status_code == 404


# ===== Vulnerabilities Extended API =====

class TestVulnerabilitiesExtendedAPI:

    def test_vulnerabilities_list(self, client):
        resp = client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200

    def test_false_positive_not_found(self, client):
        resp = client.post("/api/v1/vulnerabilities/nonexistent/false-positive", params={"reason": "test"})
        assert resp.status_code == 404

    def test_findings_recent(self, client):
        resp = client.get("/api/v1/vulnerabilities/findings/recent")
        assert resp.status_code == 200
        assert "count" in resp.json()

    def test_findings_by_rule(self, client):
        resp = client.get("/api/v1/vulnerabilities/findings/by-rule")
        assert resp.status_code == 200
        assert "rules" in resp.json()


# ===== System Extended API =====

class TestSystemExtendedAPI:

    def test_system_info(self, client):
        resp = client.get("/api/v1/system/info")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Fusion-Security"

    def test_system_health(self, client):
        resp = client.get("/api/v1/system/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_system_health_detailed(self, client):
        resp = client.get("/api/v1/system/health/detailed")
        assert resp.status_code == 200
        data = resp.json()
        assert "database" in data
        assert "ai_backend" in data

    def test_system_model_config(self, client):
        resp = client.get("/api/v1/system/model/config")
        assert resp.status_code == 200
        assert "available" in resp.json()

    def test_system_rules(self, client):
        resp = client.get("/api/v1/system/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 34
        assert "prdid" in data["rules"][0]

    def test_system_rulesets(self, client):
        resp = client.get("/api/v1/system/rulesets")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_categories"] >= 6


# ===== Scans API =====

class TestScansAPI:

    def test_list_scans(self, client):
        resp = client.get("/api/v1/scans")
        assert resp.status_code == 200

    def test_incremental_scan_endpoint_exists(self, client):
        resp = client.post("/api/v1/scans/incremental", json={
            "path": "/tmp/nonexistent",
            "base": "HEAD~1",
            "head": "HEAD",
        })
        assert resp.status_code in (200, 400, 500)
