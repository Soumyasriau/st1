"""
Integration and End-to-End tests for ThreatLens AI Flask application and Database Layer.
"""

import os
import tempfile
import json
import pytest
from app import app
from database import (
    init_db,
    save_assessment,
    get_all_assessments,
    get_assessment_by_id,
    delete_assessment,
    update_threat_risk,
    update_mitigation_status,
    get_dashboard_metrics
)
from sample_data import get_sample_assessment


@pytest.fixture
def test_db():
    """Create a temporary SQLite database for test isolation."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def client():
    """Create a Flask test client with test configuration."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


class TestDatabaseLayer:
    """Test suite verifying SQLite persistence, cascades, and updates."""

    def test_save_and_retrieve_assessment(self, test_db):
        sample = get_sample_assessment("vulnerable")
        assessment_id = save_assessment(sample, test_db)
        assert assessment_id > 0

        retrieved = get_assessment_by_id(assessment_id, test_db)
        assert retrieved is not None
        assert retrieved["hostname"] == sample["hostname"]
        assert retrieved["overall_score"] == sample["overall_score"]
        assert len(retrieved["findings"]) == len(sample["findings"])
        assert len(retrieved["threat_scenarios"]) == len(sample["threat_scenarios"])

    def test_update_threat_risk(self, test_db):
        sample = get_sample_assessment("vulnerable")
        assessment_id = save_assessment(sample, test_db)
        threat_id = sample["threat_scenarios"][0]["threat_id"]

        # Update likelihood to 5 and impact to 5 -> Risk Score 25 (Critical)
        res = update_threat_risk(threat_id, assessment_id, 5, 5, test_db)
        assert res["risk_score"] == 25
        assert res["severity"] == "Critical"

        # Verify persisted in database
        updated = get_assessment_by_id(assessment_id, test_db)
        target_t = next(t for t in updated["threat_scenarios"] if t["threat_id"] == threat_id)
        assert target_t["likelihood"] == 5
        assert target_t["impact"] == 5
        assert target_t["risk_score"] == 25
        assert target_t["severity"] == "Critical"

    def test_update_mitigation_workflow(self, test_db):
        sample = get_sample_assessment("vulnerable")
        assessment_id = save_assessment(sample, test_db)
        threat_id = sample["threat_scenarios"][0]["threat_id"]

        success = update_mitigation_status(threat_id, assessment_id, "Mitigated", "Fixed HSTS in nginx.conf", test_db)
        assert success is True

        retrieved = get_assessment_by_id(assessment_id, test_db)
        assert threat_id in retrieved["mitigation_statuses"]
        assert retrieved["mitigation_statuses"][threat_id]["status"] == "Mitigated"

    def test_delete_assessment_cascades(self, test_db):
        sample = get_sample_assessment("vulnerable")
        assessment_id = save_assessment(sample, test_db)

        deleted = delete_assessment(assessment_id, test_db)
        assert deleted is True

        # Ensure assessment and sub-records are gone
        assert get_assessment_by_id(assessment_id, test_db) is None
        all_assessments = get_all_assessments(db_path=test_db)
        assert len(all_assessments) == 0

    def test_dashboard_metrics_aggregation(self, test_db):
        sample1 = get_sample_assessment("vulnerable")
        sample2 = get_sample_assessment("hardened")
        save_assessment(sample1, test_db)
        save_assessment(sample2, test_db)

        metrics = get_dashboard_metrics(test_db)
        assert metrics["total_assessments"] == 2
        assert metrics["total_findings"] > 0
        assert metrics["critical_threats"] > 0
        assert len(metrics["recent_assessments"]) == 2


class TestFlaskApplicationRoutes:
    """Test suite exercising HTTP routes and API endpoints."""

    def test_homepage_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"ThreatLens" in resp.data
        assert b"Analyze Website" in resp.data

    def test_sample_loading_route(self, client):
        resp = client.get("/sample/vulnerable", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Insecure Legacy" in resp.data or b"Results" in resp.data or b"TL-FIND" in resp.data

    def test_dashboard_renders(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_history_renders(self, client):
        resp = client.get("/history")
        assert resp.status_code == 200
        assert b"Assessment History" in resp.data

    def test_ssrf_blocking_via_form_post(self, client):
        # Attempt to scan localhost loopback
        resp = client.post("/analyze", data={"url": "http://127.0.0.1:8080"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"SSRF Protection" in resp.data or b"restricted IP" in resp.data

    def test_json_export_endpoint(self, client):
        # Load sample first
        load_resp = client.get("/sample/hardened")
        # Extract assessment ID from redirect location
        assessment_id = load_resp.headers["Location"].split("/")[-1]

        resp = client.get(f"/report/{assessment_id}/export/json")
        assert resp.status_code == 200
        assert resp.content_type == "application/json"
        data = json.loads(resp.data)
        assert data["overall_score"] == 95
        assert "findings" in data

    def test_pdf_export_endpoint(self, client):
        load_resp = client.get("/sample/hardened")
        assessment_id = load_resp.headers["Location"].split("/")[-1]

        resp = client.get(f"/report/{assessment_id}/export/pdf")
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
        assert resp.data.startswith(b"%PDF")

    def test_api_threat_risk_recalculation(self, client):
        load_resp = client.get("/sample/vulnerable")
        assessment_id = int(load_resp.headers["Location"].split("/")[-1])

        resp = client.post(
            f"/api/threat/{assessment_id}/TL-THR-01/risk",
            json={"likelihood": 4, "impact": 4}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["risk_score"] == 16
        assert data["data"]["severity"] == "High"
