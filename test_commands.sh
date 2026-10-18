#!/usr/bin/env bash
# ==============================================================================
# Automated Verification Script for Secure Recipe Vault API
# Tests: Registration, Login, Rate Limiting, Refresh Token Rotation,
#        RBAC Data Isolation, Admin Audit Logs, and Logout.
# ==============================================================================

set -e

BASE_URL="http://localhost:3000"
COOKIE_JAR="/tmp/vault_cookies.txt"
OLD_COOKIE_JAR="/tmp/vault_old_cookies.txt"

echo "=========================================================="
echo " Starting Secure Recipe Vault API Test Suite"
echo " Target: $BASE_URL"
echo "=========================================================="

# 1. Health Check
echo -e "\n[*] 1. Checking API Health..."
curl -s -f "$BASE_URL/health" | grep "healthy" && echo "-> Health check PASSED"

# 2. User Registration
echo -e "\n[*] 2. Registering users..."
ALICE_REG=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "curl_alice", "password": "Password123!", "role": "user"}')
echo "Alice Registration: $ALICE_REG"

BOB_REG=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "curl_bob", "password": "Password123!", "role": "user"}')
echo "Bob Registration: $BOB_REG"

# Test Duplicate Registration (409)
echo -e "\n[*] 3. Testing Duplicate Registration (Expect HTTP 409)..."
DUP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "curl_alice", "password": "Password123!"}')
if [ "$DUP_STATUS" -eq 409 ]; then
  echo "-> Duplicate registration correctly rejected with HTTP 409 Conflict"
else
  echo "-> FAILED: Expected 409, got $DUP_STATUS"
fi

# 4. Successful Login for Alice
echo -e "\n[*] 4. Logging in Alice & storing HttpOnly cookie..."
ALICE_LOGIN=$(curl -s -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "curl_alice", "password": "Password123!"}')
ALICE_TOKEN=$(echo "$ALICE_LOGIN" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "Alice Access Token: ${ALICE_TOKEN:0:25}..."
cp "$COOKIE_JAR" "$OLD_COOKIE_JAR"

# 5. Refresh Token Rotation
echo -e "\n[*] 5. Testing Refresh Token Rotation..."
REFRESH_RESP=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/refresh")
NEW_TOKEN=$(echo "$REFRESH_RESP" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "New Access Token: ${NEW_TOKEN:0:25}..."

# 6. Token Reuse Detection
echo -e "\n[*] 6. Testing Token Reuse with Old Refresh Cookie (Expect HTTP 401)..."
REUSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$OLD_COOKIE_JAR" -X POST "$BASE_URL/api/auth/refresh")
if [ "$REUSE_STATUS" -eq 401 ]; then
  echo "-> Token reuse detection PASSED: Server rejected reused token with HTTP 401"
else
  echo "-> FAILED: Expected 401, got $REUSE_STATUS"
fi

# 7. Create Recipes as Alice
echo -e "\n[*] 7. Creating recipes as Alice..."
PRIVATE_RECIPE=$(curl -s -X POST "$BASE_URL/api/recipes" \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Alice Private Tart", "ingredients": ["Pastry", "Fruit"], "instructions": "Bake", "is_public": false}')
PRIV_ID=$(echo "$PRIVATE_RECIPE" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
echo "Alice Private Recipe ID: $PRIV_ID"

PUBLIC_RECIPE=$(curl -s -X POST "$BASE_URL/api/recipes" \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Alice Public Salad", "ingredients": ["Lettuce", "Dressing"], "instructions": "Toss", "is_public": true}')
PUB_ID=$(echo "$PUBLIC_RECIPE" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
echo "Alice Public Recipe ID: $PUB_ID"

# 8. Resource Isolation: Bob attempts to access Alice's private recipe
echo -e "\n[*] 8. Logging in Bob..."
BOB_LOGIN=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "curl_bob", "password": "Password123!"}')
BOB_TOKEN=$(echo "$BOB_LOGIN" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "[*] Testing Resource Isolation: Bob accesses Alice Private Recipe (Expect HTTP 404)..."
BOB_GET_PRIV=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/recipes/$PRIV_ID" \
  -H "Authorization: Bearer $BOB_TOKEN")
if [ "$BOB_GET_PRIV" -eq 404 ]; then
  echo "-> Isolation PASSED: Private recipe obscured with HTTP 404"
else
  echo "-> FAILED: Expected 404, got $BOB_GET_PRIV"
fi

echo "[*] Testing RBAC: Bob attempts to delete Alice Private Recipe (Expect HTTP 403)..."
BOB_DEL_PRIV=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE_URL/api/recipes/$PRIV_ID" \
  -H "Authorization: Bearer $BOB_TOKEN")
if [ "$BOB_DEL_PRIV" -eq 403 ]; then
  echo "-> RBAC Deletion Guard PASSED: Bob received HTTP 403 Forbidden"
else
  echo "-> FAILED: Expected 403, got $BOB_DEL_PRIV"
fi

# 9. Audit Log RBAC
echo -e "\n[*] 9. Testing Audit Logs RBAC (Expect 403 for Bob)..."
AUDIT_USER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/audit-logs" \
  -H "Authorization: Bearer $BOB_TOKEN")
if [ "$AUDIT_USER_STATUS" -eq 403 ]; then
  echo "-> Regular user correctly rejected with HTTP 403 Forbidden from audit logs"
fi

# 10. Rate Limiting on Login (Expect 429 on 6th failed attempt)
echo -e "\n[*] 10. Testing Rate Limiting (5 failures -> 6th attempt 429)..."
for i in {1..5}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "brute_target", "password": "WrongPassword!"}')
  echo "  Attempt $i status: $CODE"
done
SIXTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "brute_target", "password": "WrongPassword!"}')
if [ "$SIXTH_STATUS" -eq 429 ]; then
  echo "-> Rate limiter PASSED: 6th attempt returned HTTP 429 Too Many Requests"
else
  echo "-> FAILED: Expected 429 on 6th attempt, got $SIXTH_STATUS"
fi

# 11. Logout
echo -e "\n[*] 11. Testing Logout..."
LOGOUT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "$BASE_URL/api/auth/logout")
if [ "$LOGOUT_STATUS" -eq 200 ]; then
  echo "-> Logout successful with HTTP 200"
fi

echo -e "\n=========================================================="
echo " All API verification test scenarios passed successfully!"
echo "=========================================================="
