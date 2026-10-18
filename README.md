#  Secure Recipe Vault API

A production-grade, multi-user REST API for a **Secret Recipes Vault** built with **FastAPI**, **SQLAlchemy**, and **PostgreSQL / SQLite**. It implements advanced defense-in-depth security patterns including:

-  **Dual-Token Authentication**: Short-lived JSON Web Tokens (JWT, 15m) paired with long-lived Refresh Tokens (7d).
-  **Refresh Token Rotation (RTR)**: Stateful database allowlist tracking with immediate rotation and token reuse detection.
-  **XSS & CSRF Hardening**: Refresh tokens transported strictly via `HttpOnly`, `SameSite=Strict` cookies.
-  **Role-Based Access Control (RBAC)**: Fine-grained permissions across `user`, `curator`, and `admin` roles.
-  **Data & Resource Isolation**: Multi-tenant data segregation ensuring private recipes remain completely invisible to unauthorized users.
-  **Brute-Force Rate Limiting**: Rolling 5-minute sliding window rate limiter (max 5 failed attempts per IP or username before returning HTTP 429).
-  **Security Audit Logging**: Dedicated admin-only audit trail logging registrations, logins, rotations, and violations.

---

##  System Architecture

```
                    ┌────────────────────────┐
                    │ Client / Browser / SPA │
                    └───────────┬────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │ 1. POST /login        │ 5. GET /recipes       │ 10. POST /refresh
        │ (Credentials)         │ (Bearer JWT)          │ (HttpOnly Cookie)
        ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Auth Controller  │    │ Auth & RBAC      │    │ Refresh Service  │
│ & Rate Limiter   │    │ Middleware Guard │    │ (Allowlist DB)   │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
         │                       │                       │
         │ Verify Hash           │ Verify Signature      │ Verify Expiration
         ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Users Table    │    │  Recipes Table   │    │  Refresh Tokens  │
│ (Bcrypt Salt 12) │    │  (Public/Priv)   │    │    Allowlist     │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

---

##  Repository Structure

```
secure-recipe-vault/
├── .env.example              # Environment variables template
├── .env                      # Local environment configuration
├── .gitignore                # Git ignore rules
├── Dockerfile                # Production Docker container image
├── docker-compose.yml        # Docker Compose configuration (FastAPI + PostgreSQL)
├── requirements.txt          # Python dependencies
├── README.md                 # Primary documentation
├── THREAT_MODEL.md           # Required security and threat modeling analysis
├── test_commands.sh          # cURL bash test script (Linux / macOS)
├── test_commands.ps1         # PowerShell test script (Windows)
├── recipe_vault_postman_collection.json # Ready-to-import Postman Collection
├── src/
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py       # Pydantic BaseSettings & duration parsers
│   ├── database/
│   │   ├── __init__.py
│   │   └── session.py        # SQLAlchemy 2.0 engine, sessions, foreign key hooks
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py           # User entity with UUID and role
│   │   ├── refresh_token.py  # Refresh token allowlist entity
│   │   ├── recipe.py         # Recipe entity with public/private visibility
│   │   └── audit_log.py      # Security audit log entity
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth.py           # JWT Bearer authentication guard
│   │   ├── rbac.py           # Role-based access control guard factory
│   │   └── rate_limiter.py   # Sliding-window rate limiter for failed logins
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py   # Registration, login, token rotation, logout
│   │   ├── recipe_service.py # Recipe CRUD & query-level isolation
│   │   └── audit_service.py  # Security event recording & admin querying
│   ├── controllers/
│   │   ├── __init__.py
│   │   ├── auth_controller.py   # /api/auth routes
│   │   ├── recipe_controller.py # /api/recipes routes
│   │   └── audit_controller.py  # /api/audit-logs route
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── hash.py           # Bcrypt hashing with 12 salt rounds
│   │   ├── tokens.py         # JWT issuance, claims signing, verification
│   │   └── seed.py           # Database seeder with sample accounts & recipes
│   └── main.py               # FastAPI application setup, CORS & lifespan
└── tests/
    ├── __init__.py
    ├── conftest.py           # Isolated in-memory SQLite fixtures & test client
    ├── test_auth.py          # Registration, login, logout tests
    ├── test_rate_limit.py    # 5 failed attempts -> 6th attempt 429 tests
    ├── test_tokens_and_rotation.py # Expiration, rotation, and reuse rejection
    ├── test_recipes_rbac.py  # Recipe CRUD, RBAC, and data isolation
    └── test_audit_logs.py    # Admin-only audit logs access tests
```

---

##  Getting Started

### Prerequisites
- **Python 3.10+** (tested on Python 3.12)
- **pip** package manager
- *(Optional)* Docker & Docker Compose

### 1. Installation & Environment Setup

Clone this repository and navigate into the project directory:
```bash
git clone https://github.com/your-username/secure-recipe-vault.git
cd secure-recipe-vault
```

Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Initialize environment configuration from template:
```bash
cp .env.example .env
```

### 2. Database Initialization & Seeding

Run the seed script to create initial schema tables and populate sample users and recipes:
```bash
python -m src.utils.seed
```

**Pre-seeded Demo Accounts:**
| Username | Password | Role | Description |
|---|---|---|---|
| `admin` | `Admin123!` | `admin` | Full administrative access & audit logs |
| `curator` | `Curator123!` | `curator` | Can view and edit/delete all public recipes |
| `chef_alice` | `Alice123!` | `user` | Standard chef with public & private recipes |
| `chef_bob` | `Bob12345!` | `user` | Standard chef with private recipes |

### 3. Running the Server

Start the application with Uvicorn:
```bash
python -m uvicorn src.main:app --host 0.0.0.0 --port 3000 --reload
```
The API is now running at `http://localhost:3000`.
- Interactive Swagger UI: `http://localhost:3000/docs`
- Redoc Documentation: `http://localhost:3000/redoc`

---

##  Running with Docker Compose

To start the API together with a production-ready PostgreSQL 16 database:
```bash
docker-compose up --build
```
This launches:
- `api`: FastAPI application on port `3000`
- `db`: PostgreSQL instance on port `5432` with healthcheck and persistent volume

---

##  API Contract Specification

### 1. Authentication Endpoints

#### Register User
- **Method**: `POST /api/auth/register`
- **Request Body**:
  ```json
  {
    "username": "chef_mario",
    "password": "SecretPassword123!",
    "role": "user"
  }
  ```
- **Response (201 Created)**:
  ```json
  {
    "message": "User registered successfully",
    "id": "e4277da2-0544-42b7-8ffb-272da6bfb8e9"
  }
  ```
- **Error (409 Conflict)**: Returned if username is already taken.

#### Login
- **Method**: `POST /api/auth/login`
- **Rate Limit**: Maximum 5 failed attempts per IP or username within a rolling 5-minute window. Exceeding triggers **HTTP 429 Too Many Requests**.
- **Request Body**:
  ```json
  {
    "username": "chef_mario",
    "password": "SecretPassword123!"
  }
  ```
- **Response (200 OK)**:
  - **Header**: `Set-Cookie: refresh_token=<secure_token>; HttpOnly; SameSite=Strict; Max-Age=604800; Path=/`
  - **Body**:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
    ```

#### Refresh Token Rotation
- **Method**: `POST /api/auth/refresh`
- **Request**: Automatic browser transmission of `refresh_token` cookie.
- **Behavior**:
  - Validates cookie against database allowlist.
  - Deletes old refresh token immediately.
  - Issues new rotated refresh token in `Set-Cookie` and new access token in body.
  - If token was already rotated (reuse attempt) or expired, returns **HTTP 401 Unauthorized**.
- **Response (200 OK)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

#### Logout
- **Method**: `POST /api/auth/logout`
- **Request**: Transmits `refresh_token` cookie.
- **Behavior**: Deletes token from server database allowlist and instructs browser to expire the cookie.
- **Response (200 OK)**:
  ```json
  {
    "message": "Logged out successfully"
  }
  ```

---

### 2. Recipe Management Endpoints

All recipe endpoints require `Authorization: Bearer <access_token>`.

#### Create Recipe
- **Method**: `POST /api/recipes`
- **Request Body**:
  ```json
  {
    "title": "Secret Risotto",
    "ingredients": ["Arborio Rice", "Truffle Butter", "Parmesan"],
    "instructions": "Toast rice, slowly add hot broth, finish with butter.",
    "is_public": false
  }
  ```
- **Response (201 Created)**: Returns the newly created recipe object with `id` and `author_id`.

#### List Recipes (RBAC Isolated)
- **Method**: `GET /api/recipes`
- **Data Isolation Rules**:
  - `user`: Returns all public recipes + user's own private recipes.
  - `curator`: Returns all public recipes + curator's own private recipes.
  - `admin`: Returns all public recipes + admin's own private recipes.
  - **Zero Leakage**: Private recipes belonging to other users are never returned.

#### Get Single Recipe
- **Method**: `GET /api/recipes/{id}`
- **Behavior**: Accessible if the recipe is public or authored by the requester. Returns **HTTP 404 Not Found** for private recipes belonging to other users (obscuring existence).

#### Update Recipe
- **Method**: `PUT /api/recipes/{id}`
- **Permissions**:
  - Author can update any recipe they own (public or private).
  - Curators and Admins can update any public recipe.
  - Modifying another user's private recipe returns **HTTP 403 Forbidden**.

#### Delete Recipe
- **Method**: `DELETE /api/recipes/{id}`
- **Permissions**:
  - Base users can only delete recipes they authored.
  - Curators and Admins can delete their own recipes OR any public recipe.
  - Attempting to delete another user's private recipe returns **HTTP 403 Forbidden**.

---

### 3. Security Audit Logs Endpoint (Admin Only)

- **Method**: `GET /api/audit-logs`
- **Headers**: `Authorization: Bearer <admin_access_token>`
- **Permissions**: **Strictly Admin-Only**. Requests from `user` or `curator` roles are aggressively rejected with **HTTP 403 Forbidden**.
- **Response (200 OK)**:
  ```json
  [
    {
      "id": "f51b9e28-a40a-4a6f-9988-cb160c888e23",
      "event_type": "LOGIN_SUCCESS",
      "username": "chef_alice",
      "ip_address": "127.0.0.1",
      "details": "Issued access token and refresh token id ...",
      "created_at": "2026-10-18T10:30:00"
    }
  ]
  ```

---

##  Automated Testing

### 1. Pytest Suite
Run the automated test suite with full verbose output:
```bash
python -m pytest -v
```

All 18 comprehensive tests cover:
-  Password hashing with unique salts (bcrypt 12 rounds)
-  Input validation & duplicate username rejection (409 Conflict)
-  Successful login and `HttpOnly; SameSite=Strict` cookie verification
-  Failed login tracking & 5-failure rate limit lock (429 Too Many Requests)
-  JWT access token claims verification (`sub`, `role`, `type`, `exp`)
-  Token expiration handling (401 on expired tokens)
-  Refresh Token Rotation (RTR) and token reuse detection (401 on reused tokens)
-  Logout server-side invalidation
-  Recipe creation and retrieval data isolation
-  Recipe mutation/deletion RBAC (owner vs curator vs unauthorized user)
-  Strict admin-only protection on audit logs

### 2. cURL Verification Script (Linux / macOS)
```bash
chmod +x test_commands.sh
./test_commands.sh
```

### 3. PowerShell Verification Script (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File .\test_commands.ps1
```

### 4. Postman Collection
Import `recipe_vault_postman_collection.json` into Postman or Insomnia. It includes automated test scripts that dynamically capture the `access_token` and verify response codes.

---

##  Threat Modeling & Security Architecture

For an in-depth security analysis covering:
1. **Cross-Site Scripting (XSS)** mitigation via `HttpOnly` cookies and memory-only access tokens
2. **Cross-Site Request Forgery (CSRF)** mitigation via `SameSite=Strict` and mandatory `Authorization: Bearer` headers
3. **Token Theft & Session Replay** defense via 15-minute access tokens, database allowlist, and Refresh Token Rotation
4. **Database Breach Mitigations** via Bcrypt (12 rounds) with per-user cryptographic salts and parameterized ORM queries

Please refer to the comprehensive [THREAT_MODEL.md](THREAT_MODEL.md) file.
# Secure-Recipe-Vault-API
