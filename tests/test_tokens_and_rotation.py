import time
import jwt
from src.config.settings import settings
from src.utils.tokens import generate_access_token


def test_access_token_claims_and_algorithm(client):
    client.post("/api/auth/register", json={
        "username": "claims_tester",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "username": "claims_tester",
        "password": "Password123!"
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Decode without verifying expiration to inspect claims & header
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS256"

    decoded = jwt.decode(token, settings.JWT_ACCESS_SECRET, algorithms=["HS256"])
    assert "sub" in decoded
    assert decoded["role"] == "user"
    assert decoded["type"] == "access"
    assert "exp" in decoded
    assert decoded["exp"] > decoded["iat"]


def test_access_token_expiration(client):
    # Register user
    reg_res = client.post("/api/auth/register", json={
        "username": "expiry_tester",
        "password": "Password123!"
    })
    user_id = reg_res.json()["id"]

    # Generate a short-lived token valid for only 1 second
    short_lived_token = generate_access_token(user_id=user_id, role="user", expires_in_seconds=1)

    # Immediately requesting recipes should succeed (or return 200 empty list)
    valid_res = client.get("/api/recipes", headers={"Authorization": f"Bearer {short_lived_token}"})
    assert valid_res.status_code == 200

    # Wait for the token to expire
    time.sleep(1.5)

    # Calling after expiry must return 401 Unauthorized
    expired_res = client.get("/api/recipes", headers={"Authorization": f"Bearer {short_lived_token}"})
    assert expired_res.status_code == 401
    assert "expired" in expired_res.json()["detail"].lower()


def test_refresh_token_rotation_and_reuse_detection(client):
    """
    Scenario:
    1. Log in, extract original refresh cookie.
    2. Hit /api/auth/refresh -> 200 OK with new access_token & new rotated cookie.
    3. Hit /api/auth/refresh again with original cookie -> 401 Unauthorized (Reuse detection).
    4. Hit /api/auth/refresh with the new rotated cookie -> 200 OK (Rotation chain continues).
    """
    client.post("/api/auth/register", json={
        "username": "rotation_tester",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "username": "rotation_tester",
        "password": "Password123!"
    })
    assert login_res.status_code == 200
    original_refresh_token = login_res.cookies.get("refresh_token")
    assert original_refresh_token is not None

    # Step 2: First rotation
    first_refresh = client.post("/api/auth/refresh", cookies={"refresh_token": original_refresh_token})
    assert first_refresh.status_code == 200
    first_new_access_token = first_refresh.json()["access_token"]
    first_new_refresh_token = first_refresh.cookies.get("refresh_token")
    assert first_new_access_token is not None
    assert first_new_refresh_token is not None
    assert first_new_refresh_token != original_refresh_token

    # Step 3: Reuse detection - Attempt to use the original (now deleted) token again
    reuse_res = client.post("/api/auth/refresh", cookies={"refresh_token": original_refresh_token})
    assert reuse_res.status_code == 401
    assert "Invalid or unrecognized refresh token" in reuse_res.json()["detail"]

    # Step 4: Valid rotation using the active second token
    second_refresh = client.post("/api/auth/refresh", cookies={"refresh_token": first_new_refresh_token})
    assert second_refresh.status_code == 200
    assert "access_token" in second_refresh.json()


def test_refresh_with_missing_cookie(client):
    res = client.post("/api/auth/refresh")
    assert res.status_code == 401
