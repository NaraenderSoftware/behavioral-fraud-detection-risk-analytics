import pytest
import json
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database import init_database, get_connection


@pytest.fixture(autouse=True)
def isolate_test_db(tmp_path, monkeypatch):
    import database
    from app import seed_initial_data_if_empty
    test_db = str(tmp_path / "test_fraudguard.db")
    monkeypatch.setattr(database, "SQLITE_DB_PATH", test_db)
    database.init_database()
    seed_initial_data_if_empty()
    yield


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ============================================================
# API HEALTH TEST
# ============================================================

def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "FraudGuard Risk Engine"
    assert data["database"] == "connected"


# ============================================================
# SIGNUP ENDPOINT TESTS
# ============================================================

def test_signup_clean_account(client):
    payload = {
        "name": "Alice Cooper",
        "email": "alice.cooper@corporaterealty.com",
        "screen_width": 1920,
        "screen_height": 1080,
        "timezone": "America/Chicago",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
        "form_fill_time": 15.4,
        "mouse_movements": 45,
        "click_count": 5,
        "paste_count": 0,
        "focus_changes": 0,
    }
    response = client.post(
        "/api/signup",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data["action"] == "ALLOW"
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 30
    assert "user_id" in data


def test_signup_synthetic_disposable_email(client):
    payload = {
        "name": "Bot Tester",
        "email": "promohunter99@tempmail.com",
        "screen_width": 1366,
        "screen_height": 768,
        "timezone": "UTC",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "form_fill_time": 1.2,
        "mouse_movements": 1,
        "click_count": 1,
        "paste_count": 3,
        "focus_changes": 4,
    }
    response = client.post(
        "/api/signup",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data["risk_score"] >= 30
    signal_types = [s["type"] for s in data["signals"]]
    assert "DISPOSABLE_EMAIL" in signal_types
    assert "FAST_FORM_COMPLETION" in signal_types


def test_signup_validation_missing_fields(client):
    response = client.post(
        "/api/signup",
        data=json.dumps({"name": ""}),
        content_type="application/json"
    )
    assert response.status_code == 400
    assert "Name and email are required" in response.get_json()["error"]


def test_signup_validation_invalid_json(client):
    response = client.post(
        "/api/signup",
        data="invalid_raw_string",
        content_type="application/json"
    )
    assert response.status_code == 400


# ============================================================
# USERS & USER DETAIL TESTS
# ============================================================

def test_get_users_list(client):
    response = client.get("/api/users")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_get_user_detail_valid_and_not_found(client):
    # Retrieve first user
    users_resp = client.get("/api/users")
    users = users_resp.get_json()
    first_id = users[0]["id"]

    detail_resp = client.get(f"/api/users/{first_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.get_json()
    assert "user" in detail
    assert "signals" in detail
    assert "assessments" in detail

    # Not found case
    nf_resp = client.get("/api/users/999999")
    assert nf_resp.status_code == 404


# ============================================================
# INTERACTIVE VERIFICATION (CHALLENGE TIER)
# ============================================================

def test_verify_user_endpoint(client):
    # Retrieve an existing user
    users = client.get("/api/users").get_json()
    uid = users[0]["id"]

    response = client.post(f"/api/verify/{uid}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "verified"
    assert data["user_id"] == uid


# ============================================================
# CLUSTERS & ADMIN ACTIONS
# ============================================================

def test_get_clusters_and_action(client):
    clusters_resp = client.get("/api/clusters")
    assert clusters_resp.status_code == 200
    clusters = clusters_resp.get_json()
    assert isinstance(clusters, list)

    if clusters:
        cid = clusters[0]["id"]
        # Update status to FLAGGED
        action_resp = client.post(
            f"/api/clusters/{cid}/action",
            data=json.dumps({"status": "FLAGGED"}),
            content_type="application/json"
        )
        assert action_resp.status_code == 200
        assert action_resp.get_json()["new_status"] == "FLAGGED"

        # Invalid status
        invalid_resp = client.post(
            f"/api/clusters/{cid}/action",
            data=json.dumps({"status": "INVALID_STATUS"}),
            content_type="application/json"
        )
        assert invalid_resp.status_code == 400


# ============================================================
# DASHBOARD STATS
# ============================================================

def test_dashboard_metrics(client):
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_users" in data
    assert "high_risk" in data
    assert "blocked" in data
    assert "risk_distribution" in data
    assert len(data["risk_distribution"]) == 4  # LOW, MEDIUM, HIGH, CRITICAL


# ============================================================
# DEMO RESET
# ============================================================

def test_reset_demo_procedure(client):
    response = client.post("/api/reset-demo")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "reset complete"

    # Confirm baseline data was re-seeded
    users = client.get("/api/users").get_json()
    assert len(users) >= 6


# ============================================================
# DATABASE CONSTRAINTS & ROLLBACK
# ============================================================

def test_database_foreign_key_and_rollback():
    import sqlite3

    conn = get_connection()
    cur = conn.cursor()

    # 1. Foreign key constraint enforcement
    with pytest.raises(sqlite3.IntegrityError):
        cur.execute(
            """
            INSERT INTO risk_signals (user_id, signal_type, severity, points, message, created_at)
            VALUES (999999, 'INVALID', 'LOW', 5, 'test', '2026-01-01')
            """
        )
        conn.commit()
    conn.rollback()

    # 2. Transaction rollback verification
    cur.execute("SELECT COUNT(*) AS count FROM users")
    count_before = cur.fetchone()["count"]

    cur.execute(
        """
        INSERT INTO users (name, email, created_at)
        VALUES ('Rollback Test User', 'rollback@test.com', '2026-01-01')
        """
    )
    conn.rollback()

    cur.execute("SELECT COUNT(*) AS count FROM users")
    count_after = cur.fetchone()["count"]
    assert count_before == count_after
    conn.close()


# ============================================================
# SECURITY & ADMINISTRATIVE AUTHORIZATION TESTS
# ============================================================

def test_admin_authorization_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "test-secret-key-999")

    # 1. Unauthenticated request rejected
    resp_unauth = client.post("/api/reset-demo")
    assert resp_unauth.status_code == 401
    assert "Unauthorized" in resp_unauth.get_json()["error"]

    # 2. Invalid key rejected
    resp_bad = client.post("/api/reset-demo", headers={"X-Admin-Key": "wrong-key"})
    assert resp_bad.status_code == 401

    # 3. Valid key via X-Admin-Key header accepted
    resp_ok = client.post("/api/reset-demo", headers={"X-Admin-Key": "test-secret-key-999"})
    assert resp_ok.status_code == 200

    # 4. Valid key via Authorization Bearer token accepted for cluster action
    clusters = client.get("/api/clusters").get_json()
    if clusters:
        cid = clusters[0]["id"]
        resp_bearer = client.post(
            f"/api/clusters/{cid}/action",
            headers={"Authorization": "Bearer test-secret-key-999"},
            data=json.dumps({"status": "RESTRICTED"}),
            content_type="application/json"
        )
        assert resp_bearer.status_code == 200


def test_payload_size_limit_rejection(client):
    # Oversized payload exceeding 1MB limit
    oversized = {"name": "A" * 1100000, "email": "huge@example.com"}
    response = client.post(
        "/api/signup",
        data=json.dumps(oversized),
        content_type="application/json"
    )
    assert response.status_code == 413
    assert "Payload exceeds maximum allowed size" in response.get_json()["error"]


def test_api_health_safe_error_reporting(client, monkeypatch):
    import app as app_module

    def failing_connection():
        raise RuntimeError("simulated database driver failure")

    monkeypatch.setattr(app_module, "get_connection", failing_connection)

    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    # Ensure raw exception string is not exposed to client
    assert data["database"] == "error: connection failed"
    assert "simulated database driver failure" not in data["database"]


