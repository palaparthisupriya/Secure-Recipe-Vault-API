from typing import Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status, Cookie
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from src.database.session import get_db
from src.services.auth_service import auth_service
from src.config.settings import settings


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, description="Unique username")
    password: str = Field(..., min_length=8, max_length=128, description="Plaintext password")
    role: Optional[str] = Field("user", description="Default role 'user'")


class LoginRequest(BaseModel):
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="Password")


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """
    Registers a new user account with secure bcrypt password hashing.
    Enforces uniqueness (409 Conflict) and assigns default 'user' role.
    """
    ip = get_client_ip(request)
    # Default to user role unless already valid role
    assigned_role = req.role if req.role in ("user", "curator", "admin") else "user"
    result = auth_service.register(
        db=db,
        username=req.username,
        password=req.password,
        role=assigned_role,
        ip_address=ip
    )
    return result


@router.post("/login", status_code=status.HTTP_200_OK)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates credentials, enforces rolling rate limits,
    issues JWT access token (15m) in response body,
    and sets HttpOnly SameSite=Strict refresh token cookie (7d).
    """
    ip = get_client_ip(request)
    access_token, refresh_token_str, user = auth_service.login(
        db=db,
        username=req.username,
        password=req.password,
        ip_address=ip
    )

    # Set secure HttpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token_str,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE.lower(),
        secure=settings.COOKIE_SECURE or settings.is_production,
        max_age=settings.refresh_token_expire_seconds,
        path="/"
    )

    return {"access_token": access_token}


@router.post("/refresh", status_code=status.HTTP_200_OK)
def refresh_token(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """
    Refreshes session using Refresh Token Rotation:
    - Validates refresh token from HttpOnly cookie against DB allowlist.
    - Invalidates old refresh token immediately.
    - Issues new access token in body and sets new rotated refresh token cookie.
    - Rejects invalid or reused tokens with 401 Unauthorized.
    """
    ip = get_client_ip(request)
    # Also support reading from Cookie header if Cookie param not populated by test runner
    cookie_token = refresh_token or request.cookies.get("refresh_token")

    new_access_token, new_refresh_token_str = auth_service.refresh_tokens(
        db=db,
        refresh_token_str=cookie_token,
        ip_address=ip
    )

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token_str,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE.lower(),
        secure=settings.COOKIE_SECURE or settings.is_production,
        max_age=settings.refresh_token_expire_seconds,
        path="/"
    )

    return {"access_token": new_access_token}


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """
    Performs server-side session termination:
    - Deletes refresh token from DB allowlist.
    - Instructs client browser to clear HttpOnly cookie.
    """
    ip = get_client_ip(request)
    cookie_token = refresh_token or request.cookies.get("refresh_token")

    auth_service.logout(
        db=db,
        refresh_token_str=cookie_token,
        ip_address=ip
    )

    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite=settings.COOKIE_SAMESITE.lower(),
        secure=settings.COOKIE_SECURE or settings.is_production,
        path="/"
    )

    return {"message": "Logged out successfully"}
