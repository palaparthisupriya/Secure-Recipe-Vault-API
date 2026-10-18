def test_rate_limiting_after_five_failed_attempts(client):
    # Register victim user
    client.post("/api/auth/register", json={
        "username": "victim_user",
        "password": "RealPassword123!"
    })

    # Send 5 incorrect password attempts -> all should return 401
    for attempt in range(1, 6):
        res = client.post("/api/auth/login", json={
            "username": "victim_user",
            "password": f"WrongAttempt{attempt}"
        })
        assert res.status_code == 401, f"Attempt {attempt} should return 401, got {res.status_code}"

    # 6th attempt -> must be blocked with 429 Too Many Requests
    blocked_res = client.post("/api/auth/login", json={
        "username": "victim_user",
        "password": "WrongAttempt6"
    })
    assert blocked_res.status_code == 429
    assert "Too many failed login attempts" in blocked_res.json()["detail"]
    assert "retry-after" in blocked_res.headers


def test_rate_limit_blocks_even_with_correct_password_when_locked(client):
    client.post("/api/auth/register", json={
        "username": "brute_target",
        "password": "RealPassword123!"
    })

    # Exhaust the 5 allowed attempts
    for _ in range(5):
        client.post("/api/auth/login", json={
            "username": "brute_target",
            "password": "BadPassword!"
        })

    # Attacker tries the correct password on 6th attempt while locked -> should still return 429
    locked_out_res = client.post("/api/auth/login", json={
        "username": "brute_target",
        "password": "RealPassword123!"
    })
    assert locked_out_res.status_code == 429
