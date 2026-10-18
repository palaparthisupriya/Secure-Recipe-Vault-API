from typing import Optional, Union, List, Any
from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from src.database.session import get_db
from src.middleware.auth import AuthenticatedUser, require_auth
from src.services.recipe_service import recipe_service


router = APIRouter(prefix="/api/recipes", tags=["Recipes"])


class RecipeCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Title of the recipe")
    ingredients: Union[str, List[Any]] = Field(..., description="Ingredients list or text")
    instructions: str = Field(..., min_length=1, description="Cooking instructions")
    is_public: bool = Field(False, description="Whether the recipe is visible to other users")


class RecipeUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    ingredients: Optional[Union[str, List[Any]]] = None
    instructions: Optional[str] = Field(None, min_length=1)
    is_public: Optional[bool] = None


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.post("", status_code=status.HTTP_201_CREATED)
def create_recipe(
    req: RecipeCreateRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Creates a new secret or public recipe associated with the authenticated user.
    """
    ip = get_client_ip(request)
    return recipe_service.create_recipe(
        db=db,
        user=current_user,
        title=req.title,
        ingredients=req.ingredients,
        instructions=req.instructions,
        is_public=req.is_public,
        ip_address=ip
    )


@router.get("", status_code=status.HTTP_200_OK)
def get_recipes(
    current_user: AuthenticatedUser = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Retrieves recipes according to RBAC and resource isolation:
    - All users (user, curator, admin) receive all public recipes + their own private recipes.
    - Private recipes of other users are never returned.
    """
    return recipe_service.get_recipes_for_user(db=db, user=current_user)


@router.get("/{recipe_id}", status_code=status.HTTP_200_OK)
def get_recipe(
    recipe_id: str,
    current_user: AuthenticatedUser = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Retrieves a single recipe. Returns 404 if not found or if private to another user.
    """
    return recipe_service.get_recipe_by_id(db=db, recipe_id=recipe_id, user=current_user)


@router.put("/{recipe_id}", status_code=status.HTTP_200_OK)
def update_recipe(
    recipe_id: str,
    req: RecipeUpdateRequest,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Updates recipe:
    - Allowed if user is author.
    - Allowed if recipe is public and user role is 'curator' or 'admin'.
    - Rejects unauthorized updates with 403 Forbidden.
    """
    ip = get_client_ip(request)
    return recipe_service.update_recipe(
        db=db,
        recipe_id=recipe_id,
        user=current_user,
        title=req.title,
        ingredients=req.ingredients,
        instructions=req.instructions,
        is_public=req.is_public,
        ip_address=ip
    )


@router.delete("/{recipe_id}", status_code=status.HTTP_200_OK)
def delete_recipe(
    recipe_id: str,
    request: Request,
    current_user: AuthenticatedUser = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """
    Deletes recipe:
    - Base user: Can only delete recipes they authored.
    - Curator / Admin: Can delete their own recipes OR any public recipe.
    - Private recipes of other users return 403 Forbidden.
    """
    ip = get_client_ip(request)
    return recipe_service.delete_recipe(
        db=db,
        recipe_id=recipe_id,
        user=current_user,
        ip_address=ip
    )
