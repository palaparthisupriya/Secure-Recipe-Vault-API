from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from src.utils.tokens import decode_access_token


security_bearer = HTTPBearer(auto_error=False)


class AuthenticatedUser:
    def __init__(self, user_id: str, role: str, raw_payload: Dict[str, Any]):
        self.id = user_id
        self.sub = user_id
        self.role = role
        self.raw = raw_payload

    def __repr__(self):
        return f"<AuthenticatedUser(id='{self.id}', role='{self.role}')>"


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> AuthenticatedUser:
    """
    Authentication Guard dependency.
    Validates Authorization: Bearer <jwt> header, cryptographically verifies the token,
    and returns the AuthenticatedUser object.
    Raises 401 Unauthorized if missing, expired, or invalid.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has expired\""}
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""}
        )

    user_id = payload.get("sub")
    role = payload.get("role")
    if not user_id or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing required claims",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = AuthenticatedUser(user_id=user_id, role=role, raw_payload=payload)
    request.state.user = user
    return user
