def test_unauthenticated_recipe_access_rejected(client):
    res = client.get("/api/recipes")
    assert res.status_code == 401
    assert "Missing or invalid authorization header" in res.json()["detail"]


def test_recipe_crud_and_rbac_isolation(client, seed_users):
    # Log in test_user1 (role: user)
    user1_login = client.post("/api/auth/login", json={"username": "test_user1", "password": "Password123!"})
    token1 = user1_login.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # Log in test_user2 (role: user)
    user2_login = client.post("/api/auth/login", json={"username": "test_user2", "password": "Password123!"})
    token2 = user2_login.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Log in test_curator (role: curator)
    curator_login = client.post("/api/auth/login", json={"username": "test_curator", "password": "Password123!"})
    token_curator = curator_login.json()["access_token"]
    headers_curator = {"Authorization": f"Bearer {token_curator}"}

    # 1. User 1 creates a private recipe and a public recipe
    res_private1 = client.post("/api/recipes", headers=headers1, json={
        "title": "User 1 Secret Chili",
        "ingredients": ["Beef", "Beans", "Ghost Pepper"],
        "instructions": "Slow cook for 6 hours.",
        "is_public": False
    })
    assert res_private1.status_code == 201
    private1_id = res_private1.json()["id"]

    res_public1 = client.post("/api/recipes", headers=headers1, json={
        "title": "User 1 Public Cookies",
        "ingredients": ["Flour", "Sugar", "Chocolate Chips"],
        "instructions": "Bake at 350F for 12 minutes.",
        "is_public": True
    })
    assert res_public1.status_code == 201
    public1_id = res_public1.json()["id"]

    # 2. User 2 creates a private recipe
    res_private2 = client.post("/api/recipes", headers=headers2, json={
        "title": "User 2 Secret BBQ Sauce",
        "ingredients": ["Molasses", "Vinegar", "Spices"],
        "instructions": "Simmer on low.",
        "is_public": False
    })
    assert res_private2.status_code == 201
    private2_id = res_private2.json()["id"]

    # 3. Test Retrieval Isolation for User 1
    # User 1 should see: their private chili, their public cookies. Should NOT see User 2's BBQ sauce.
    user1_recipes = client.get("/api/recipes", headers=headers1).json()
    user1_titles = [r["title"] for r in user1_recipes]
    assert "User 1 Secret Chili" in user1_titles
    assert "User 1 Public Cookies" in user1_titles
    assert "User 2 Secret BBQ Sauce" not in user1_titles

    # 4. Test Retrieval Isolation for User 2
    # User 2 should see: their private BBQ sauce, User 1's public cookies. Should NOT see User 1's chili.
    user2_recipes = client.get("/api/recipes", headers=headers2).json()
    user2_titles = [r["title"] for r in user2_recipes]
    assert "User 2 Secret BBQ Sauce" in user2_titles
    assert "User 1 Public Cookies" in user2_titles
    assert "User 1 Secret Chili" not in user2_titles

    # 5. Direct ID Lookup Resource Isolation
    # User 2 attempts to GET User 1's private recipe -> MUST return 404 Not Found (obscuring existence)
    direct_get_unauthorized = client.get(f"/api/recipes/{private1_id}", headers=headers2)
    assert direct_get_unauthorized.status_code == 404

    # User 2 GET User 1's public recipe -> 200 OK
    direct_get_public = client.get(f"/api/recipes/{public1_id}", headers=headers2)
    assert direct_get_public.status_code == 200

    # 6. Deletion Permissions (User vs User)
    # User 2 attempts to delete User 1's private recipe -> 403 Forbidden
    del_forbidden = client.delete(f"/api/recipes/{private1_id}", headers=headers2)
    assert del_forbidden.status_code == 403

    # User 2 attempts to delete User 1's public recipe -> 403 Forbidden (User 2 is base user, not curator/admin)
    del_pub_user2 = client.delete(f"/api/recipes/{public1_id}", headers=headers2)
    assert del_pub_user2.status_code == 403

    # 7. Curator Permissions on Public Recipe
    # Curator attempts to update User 1's public recipe -> Allowed (200 OK)
    curator_update = client.put(f"/api/recipes/{public1_id}", headers=headers_curator, json={
        "title": "Curator Verified Chocolate Cookies"
    })
    assert curator_update.status_code == 200
    assert curator_update.json()["title"] == "Curator Verified Chocolate Cookies"

    # Curator attempts to delete User 1's PRIVATE recipe -> 403 Forbidden
    curator_del_private = client.delete(f"/api/recipes/{private1_id}", headers=headers_curator)
    assert curator_del_private.status_code == 403

    # Curator deletes User 1's PUBLIC recipe -> Allowed (200 OK)
    curator_del_public = client.delete(f"/api/recipes/{public1_id}", headers=headers_curator)
    assert curator_del_public.status_code == 200

    # 8. Author deletes their own private recipe -> Allowed (200 OK)
    author_del = client.delete(f"/api/recipes/{private1_id}", headers=headers1)
    assert author_del.status_code == 200
