# ==============================================================================
# PowerShell Test Script for Secure Recipe Vault API
# ==============================================================================

$BaseUrl = "http://localhost:3000"
$WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Secure Recipe Vault API - PowerShell Test Suite" -ForegroundColor Cyan
Write-Host " Target: $BaseUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Health check
Write-Host "`n[*] 1. Health Check..." -ForegroundColor Yellow
$health = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get
Write-Host "Health: $($health.status)" -ForegroundColor Green

# 2. Register Alice
Write-Host "`n[*] 2. Registering Alice..." -ForegroundColor Yellow
try {
    $aliceReg = Invoke-RestMethod -Uri "$BaseUrl/api/auth/register" -Method Post -ContentType "application/json" -Body '{"username":"ps_alice","password":"Password123!","role":"user"}'
    Write-Host "Alice ID: $($aliceReg.id)" -ForegroundColor Green
} catch {
    Write-Host "Alice already exists or registered: $_" -ForegroundColor DarkGray
}

# 3. Duplicate Registration (Expect 409)
Write-Host "`n[*] 3. Testing Duplicate Registration (Expect 409)..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/auth/register" -Method Post -ContentType "application/json" -Body '{"username":"ps_alice","password":"Password123!"}'
    Write-Host "FAILED: Expected 409 Conflict" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 409) {
        Write-Host "PASSED: Duplicate correctly returned 409 Conflict" -ForegroundColor Green
    } else {
        Write-Host "Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
}

# 4. Alice Login
Write-Host "`n[*] 4. Logging in Alice..." -ForegroundColor Yellow
$loginRes = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/api/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"ps_alice","password":"Password123!"}' -SessionVariable "AliceSession"
$aliceToken = ($loginRes.Content | ConvertFrom-Json).access_token
Write-Host "Alice Access Token: $($aliceToken.Substring(0, 25))..." -ForegroundColor Green

# 5. Refresh Token Rotation
Write-Host "`n[*] 5. Testing Refresh Token Rotation..." -ForegroundColor Yellow
$refreshRes = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/api/auth/refresh" -Method Post -WebSession $AliceSession
$newToken = ($refreshRes.Content | ConvertFrom-Json).access_token
Write-Host "Rotated New Token: $($newToken.Substring(0, 25))..." -ForegroundColor Green

# 6. Create Alice Private Recipe
Write-Host "`n[*] 6. Creating Alice Private Recipe..." -ForegroundColor Yellow
$recipeHeaders = @{ "Authorization" = "Bearer $newToken" }
$recipePayload = '{"title":"Alice PowerShell Secret Stew","ingredients":["Beef","Carrots"],"instructions":"Slow cook","is_public":false}'
$newRecipe = Invoke-RestMethod -Uri "$BaseUrl/api/recipes" -Method Post -Headers $recipeHeaders -ContentType "application/json" -Body $recipePayload
$recipeId = $newRecipe.id
Write-Host "Created Recipe ID: $recipeId (is_public: $($newRecipe.is_public))" -ForegroundColor Green

# 7. Register and Login Bob
Write-Host "`n[*] 7. Registering and Logging in Bob..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/auth/register" -Method Post -ContentType "application/json" -Body '{"username":"ps_bob","password":"Password123!","role":"user"}' | Out-Null
} catch {}
$bobLogin = Invoke-RestMethod -Uri "$BaseUrl/api/auth/login" -Method Post -ContentType "application/json" -Body '{"username":"ps_bob","password":"Password123!"}'
$bobToken = $bobLogin.access_token
Write-Host "Bob Logged In Successfully" -ForegroundColor Green

# 8. Bob attempts to access Alice's Private Recipe (Expect 404)
Write-Host "`n[*] 8. Bob accesses Alice's Private Recipe (Expect 404)..." -ForegroundColor Yellow
$bobHeaders = @{ "Authorization" = "Bearer $bobToken" }
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/recipes/$recipeId" -Method Get -Headers $bobHeaders
    Write-Host "FAILED: Bob should not see private recipe" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        Write-Host "PASSED: Resource isolation obscured recipe with HTTP 404" -ForegroundColor Green
    }
}

# 9. Audit Logs RBAC Check (Expect 403 for Bob)
Write-Host "`n[*] 9. Bob accesses Audit Logs (Expect 403)..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/audit-logs" -Method Get -Headers $bobHeaders
    Write-Host "FAILED: Regular user should not access audit logs" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 403) {
        Write-Host "PASSED: Audit log protected with HTTP 403 Forbidden" -ForegroundColor Green
    }
}

# 10. Rate Limiting Test (5 failures -> 6th returns 429)
Write-Host "`n[*] 10. Testing Login Rate Limiter (Expect 429 on 6th failed attempt)..." -ForegroundColor Yellow
$targetUser = "victim_ps_" + (Get-Random)
for ($i = 1; $i -le 5; $i++) {
    try {
        Invoke-RestMethod -Uri "$BaseUrl/api/auth/login" -Method Post -ContentType "application/json" -Body "{`"username`":`"$targetUser`",`"password`":`"BadPass$i`"}"
    } catch {
        Write-Host "  Attempt $i -> HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor DarkGray
    }
}
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/auth/login" -Method Post -ContentType "application/json" -Body "{`"username`":`"$targetUser`",`"password`":`"BadPass6`"}"
    Write-Host "FAILED: Expected 429 Too Many Requests" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 429) {
        Write-Host "PASSED: 6th attempt blocked with HTTP 429 Too Many Requests" -ForegroundColor Green
    } else {
        Write-Host "Received: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " PowerShell Verification Completed Successfully!" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
