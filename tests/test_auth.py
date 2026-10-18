def test_register_success(client):
    response = client.post("/api/auth/register", json={
        "username": "new_chef",
        "password": "SecurePassword123!"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert "id" in data
    assert len(data["id"]) > 0


def test_register_duplicate_username(client):
    payload = {
        "username": "duplicate_user",
        "password": "Password123!"
    }
    first_res = client.post("/api/auth/register", json=payload)
    assert first_res.status_code == 201

    second_res = client.post("/api/auth/register", json=payload)
    assert second_res.status_code == 409
    assert "already exists" in second_res.json()["detail"]


def test_register_validation_failure(client):
    # Too short username
    res1 = client.post("/api/auth/register", json={"username": "ab", "password": "valid_password_123"})
    assert res1.status_code == 422

    # Too short password
    res2 = client.post("/api/auth/register", json={"username": "valid_user", "password": "123"})
    assert res2.status_code == 422


def test_login_success_and_cookie_attributes(client):
    # Register
    client.post("/api/auth/register", json={
        "username": "login_user",
        "password": "MySecretPassword123!"
    })

    # Login
    response = client.post("/api/auth/login", json={
        "username": "login_user",
        "password": "MySecretPassword123!"
    })

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert len(data["access_token"]) > 20

    # Verify refresh_token cookie was set
    assert "refresh_token" in response.cookies
    cookie_header = response.headers.get("set-cookie", "")
    assert "refresh_token=" in cookie_header
    assert "httponly" in cookie_header.lower()
    assert "samesite=strict" in cookie_header.lower()


def test_login_invalid_password(client):
    client.post("/api/auth/register", json={
        "username": "target_user",
        "password": "CorrectPassword123!"
    })

    response = client.post("/api/auth/login", json={
        "username": "target_user",
        "password": "WrongPassword123!"
    })
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_logout_clears_cookie_and_revokes_token(client):
    client.post("/api/auth/register", json={
        "username": "logout_user",
        "password": "Password123!"
    })

    login_res = client.post("/api/auth/login", json={
        "username": "logout_user",
        "password": "Password123!"
    })
    assert login_res.status_code == 200
    refresh_token = login_res.cookies.get("refresh_token")

    # Logout
    logout_res = client.post("/api/auth/logout", cookies={"refresh_token": refresh_token})
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Logged out successfully"

    # Attempt to refresh with the logged out token -> must fail with 401
    refresh_res = client.post("/api/auth/refresh", cookies={"refresh_token": refresh_token})
    assert refresh_res.status_code == 401
