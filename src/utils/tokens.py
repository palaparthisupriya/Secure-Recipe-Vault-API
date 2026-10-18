import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import jwt
from src.config.settings import settings


def generate_access_token(user_id: str, role: str, expires_in_seconds: Optional[int] = None) -> str:
    """
    Generates a short-lived JWT Access Token signed with HMAC-SHA256 (HS256).
    Contains sub (user ID), role, type ('access'), iat, and exp claims.
    """
    if expires_in_seconds is None:
        expires_in_seconds = settings.access_token_expire_seconds

    now = datetime.now(timezone.utc)
    expire = now + timedelta(seconds=expires_in_seconds)

    payload = {
        "sub": str(user_id),
        "role": str(role),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }

    token = jwt.encode(payload, settings.JWT_ACCESS_SECRET, algorithm="HS256")
    return token


def generate_refresh_token_string() -> str:
    """
    Generates a cryptographically strong, unguessable random string for the Refresh Token.
    Using 40 bytes of randomness (80 hex characters).
    """
    return secrets.token_hex(40)


def calculate_refresh_expiry(expires_in_seconds: Optional[int] = None) -> datetime:
    """
    Calculates the expiration datetime for a refresh token (default 7 days).
    """
    if expires_in_seconds is None:
        expires_in_seconds = settings.refresh_token_expire_seconds
    return datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and verifies the signature and expiration of an Access Token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError if invalid.
    """
    decoded = jwt.decode(
        token,
        settings.JWT_ACCESS_SECRET,
        algorithms=["HS256"],
        options={"require": ["sub", "role", "exp"]}
    )
    if decoded.get("type") != "access":
        raise jwt.InvalidTokenError("Token type must be 'access'")
    return decoded
