"""Unit tests for the FastAPI server — smoke tests for all endpoints."""
import pytest
from fastapi.testclient import TestClient

from sentinel.api.server import app

client = TestClient(app)


@pytest.mark.unit
class TestHealthEndpoint:
    def test_health_returns_200(self):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_ok_status(self):
        data = client.get("/health").json()
        assert data["status"] == "ok"

    def test_health_returns_service_name(self):
        data = client.get("/health").json()
        assert "sentinel" in data.get("service", "").lower()


@pytest.mark.unit
class TestFindingsEndpoints:
    def test_list_findings_returns_200(self):
        assert client.get("/findings/").status_code == 200

    def test_list_findings_has_findings_key(self):
        data = client.get("/findings/").json()
        assert "findings" in data

    def test_get_finding_by_id_returns_200(self):
        assert client.get("/findings/some-id").status_code == 200


@pytest.mark.unit
class TestPoliciesEndpoints:
    def test_list_policies_returns_200(self):
        assert client.get("/policies/").status_code == 200

    def test_list_policies_has_policies_key(self):
        assert "policies" in client.get("/policies/").json()


@pytest.mark.unit
class TestSkillsEndpoints:
    def test_list_skills_returns_200(self):
        assert client.get("/skills/").status_code == 200


@pytest.mark.unit
class TestAlertsEndpoints:
    def test_list_alerts_returns_200(self):
        assert client.get("/alerts/").status_code == 200
