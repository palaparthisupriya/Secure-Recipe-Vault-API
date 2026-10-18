def test_audit_logs_unauthenticated_rejected(client):
    res = client.get("/api/audit-logs")
    assert res.status_code == 401


def test_audit_logs_forbidden_for_regular_user(client, seed_users):
    user_login = client.post("/api/auth/login", json={"username": "test_user1", "password": "Password123!"})
    token = user_login.json()["access_token"]
    res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["detail"]


def test_audit_logs_forbidden_for_curator(client, seed_users):
    curator_login = client.post("/api/auth/login", json={"username": "test_curator", "password": "Password123!"})
    token = curator_login.json()["access_token"]
    res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "Insufficient permissions" in res.json()["detail"]


def test_audit_logs_accessible_only_by_admin(client, seed_users):
    admin_login = client.post("/api/auth/login", json={"username": "test_admin", "password": "Password123!"})
    token = admin_login.json()["access_token"]
    res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    logs = res.json()
    assert isinstance(logs, list)
    # Check that events like LOGIN_SUCCESS exist in the audit log
    event_types = [l["event_type"] for l in logs]
    assert "LOGIN_SUCCESS" in event_types
