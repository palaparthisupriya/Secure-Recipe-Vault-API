from typing import List, Union
from fastapi import HTTPException, status, Depends
from src.middleware.auth import AuthenticatedUser, require_auth


ROLE_HIERARCHY = {
    "user": 1,
    "curator": 2,
    "admin": 3
}


def require_role(allowed_roles: Union[List[str], str]):
    """
    Role-Based Access Control (RBAC) guard factory.
    Verifies that the authenticated user possesses one of the allowed roles.
    Raises 403 Forbidden if the user's role is not permitted.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    async def role_checker(user: AuthenticatedUser = Depends(require_auth)) -> AuthenticatedUser:
        if not user or not user.role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: No role assigned"
            )

        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Insufficient permissions"
            )

        return user

    return role_checker


# Specialized convenience guards
require_admin = require_role(["admin"])
require_curator_or_admin = require_role(["curator", "admin"])
