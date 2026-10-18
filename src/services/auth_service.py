import datetime
from datetime import timezone
from typing import Tuple, Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from src.models.user import User
from src.models.refresh_token import RefreshToken
from src.utils.hash import hash_password, verify_password
from src.utils.tokens import (
    generate_access_token,
    generate_refresh_token_string,
    calculate_refresh_expiry,
)
from src.middleware.rate_limiter import login_rate_limiter
from src.services.audit_service import audit_service


def is_token_expired(expires_at: datetime.datetime) -> bool:
    """Helper to compare token expiry handling timezone-aware and naive datetimes."""
    if expires_at.tzinfo is None:
        return expires_at < datetime.datetime.now(timezone.utc).replace(tzinfo=None)
    return expires_at < datetime.datetime.now(timezone.utc)


class AuthService:
    @staticmethod
    def register(db: Session, username: str, password: str, role: str = "user", ip_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Registers a new user:
        1. Validates uniqueness (409 Conflict if duplicate).
        2. Cryptographically hashes password with bcrypt.
        3. Enforces default 'user' role.
        4. Logs audit event.
        """
        # Validate uniqueness
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )

        hashed_pw = hash_password(password)
        new_user = User(
            username=username,
            password_hash=hashed_pw,
            role=role
        )
        db.add(new_user)
        try:
            db.commit()
            db.refresh(new_user)
        except Exception:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error during registration"
            )

        audit_service.record_event(
            db=db,
            event_type="USER_REGISTERED",
            username=username,
            ip_address=ip_address,
            details=f"User registered with id {new_user.id} and role {new_user.role}"
        )

        return {
            "message": "User registered successfully",
            "id": str(new_user.id)
        }

    @staticmethod
    def login(db: Session, username: str, password: str, ip_address: str) -> Tuple[str, str, User]:
        """
        Authenticates a user:
        1. Checks rate limiter for IP and username.
        2. Validates credentials with bcrypt constant-time check.
        3. Issues JWT Access Token (15m) and Refresh Token (7d).
        4. Persists Refresh Token to allowlist.
        5. Logs audit event.
        """
        # 1. Rate limit check (rolling 5-minute window, max 5 failed attempts)
        is_limited, retry_after = login_rate_limiter.is_rate_limited(ip=ip_address, username=username)
        if is_limited:
            audit_service.record_event(
                db=db,
                event_type="RATE_LIMIT_EXCEEDED",
                username=username,
                ip_address=ip_address,
                details=f"Rate limit triggered for IP {ip_address} or user {username}"
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Please try again after {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )

        # 2. Query user
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            login_rate_limiter.record_failure(ip=ip_address, username=username)
            audit_service.record_event(
                db=db,
                event_type="LOGIN_FAILED",
                username=username,
                ip_address=ip_address,
                details="Invalid username or password"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # 3. Successful login - clear user limiter
        login_rate_limiter.record_success(ip=ip_address, username=username)

        # 4. Generate tokens
        access_token = generate_access_token(user_id=user.id, role=user.role)
        refresh_token_str = generate_refresh_token_string()
        refresh_expiry = calculate_refresh_expiry()

        # 5. Persist to allowlist
        db_token = RefreshToken(
            user_id=user.id,
            token=refresh_token_str,
            expires_at=refresh_expiry
        )
        db.add(db_token)
        db.commit()

        audit_service.record_event(
            db=db,
            event_type="LOGIN_SUCCESS",
            username=username,
            ip_address=ip_address,
            details=f"Issued access token and refresh token id {db_token.id}"
        )

        return access_token, refresh_token_str, user

    @staticmethod
    def refresh_tokens(db: Session, refresh_token_str: Optional[str], ip_address: Optional[str]) -> Tuple[str, str]:
        """
        Refreshes tokens using Refresh Token Rotation:
        1. Looks up token in database allowlist.
        2. Validates expiration.
        3. Deletes old refresh token immediately (preventing reuse).
        4. Generates new token pair and persists new refresh token.
        5. Logs audit event.
        """
        if not refresh_token_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token cookie missing"
            )

        token_record = db.query(RefreshToken).filter(RefreshToken.token == refresh_token_str).first()
        if not token_record:
            # Token reuse detected or invalid token presented
            audit_service.record_event(
                db=db,
                event_type="TOKEN_REUSE_DETECTED",
                ip_address=ip_address,
                details="Unrecognized refresh token presented during rotation attempt"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or unrecognized refresh token"
            )

        # Check expiration
        if is_token_expired(token_record.expires_at):
            user_id = token_record.user_id
            db.delete(token_record)
            db.commit()
            audit_service.record_event(
                db=db,
                event_type="TOKEN_EXPIRED",
                ip_address=ip_address,
                details=f"Expired refresh token presented for user {user_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )

        user = db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with token no longer exists"
            )

        # Token Rotation: Delete old token immediately
        db.delete(token_record)

        # Generate new token pair
        new_access_token = generate_access_token(user_id=user.id, role=user.role)
        new_refresh_token_str = generate_refresh_token_string()
        new_refresh_expiry = calculate_refresh_expiry()

        new_token_record = RefreshToken(
            user_id=user.id,
            token=new_refresh_token_str,
            expires_at=new_refresh_expiry
        )
        db.add(new_token_record)
        db.commit()

        audit_service.record_event(
            db=db,
            event_type="TOKEN_ROTATED",
            username=user.username,
            ip_address=ip_address,
            details=f"Rotated refresh token for user {user.username}"
        )

        return new_access_token, new_refresh_token_str

    @staticmethod
    def logout(db: Session, refresh_token_str: Optional[str], ip_address: Optional[str]) -> bool:
        """
        Logs out user by invalidating the refresh token on the server allowlist.
        """
        if refresh_token_str:
            token_record = db.query(RefreshToken).filter(RefreshToken.token == refresh_token_str).first()
            if token_record:
                username = token_record.user.username if token_record.user else None
                db.delete(token_record)
                db.commit()
                audit_service.record_event(
                    db=db,
                    event_type="USER_LOGGED_OUT",
                    username=username,
                    ip_address=ip_address,
                    details="Server-side refresh token invalidated"
                )
        return True


auth_service = AuthService()
