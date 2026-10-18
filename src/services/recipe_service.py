import json
from typing import List, Optional, Union, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from src.models.recipe import Recipe
from src.middleware.auth import AuthenticatedUser
from src.services.audit_service import audit_service


def serialize_ingredients(ingredients: Union[str, List[str], List[Any]]) -> str:
    """Serializes ingredients to a stored string/JSON format."""
    if isinstance(ingredients, (list, dict)):
        return json.dumps(ingredients)
    return str(ingredients)


def parse_ingredients(ingredients_str: str) -> Union[List[str], str]:
    """Parses ingredients string back into python structure if JSON formatted."""
    try:
        return json.loads(ingredients_str)
    except Exception:
        return ingredients_str


def recipe_to_dict(recipe: Recipe) -> Dict[str, Any]:
    return {
        "id": str(recipe.id),
        "author_id": str(recipe.author_id),
        "title": recipe.title,
        "ingredients": parse_ingredients(recipe.ingredients),
        "instructions": recipe.instructions,
        "is_public": recipe.is_public,
        "created_at": recipe.created_at.isoformat() if recipe.created_at else None
    }


class RecipeService:
    @staticmethod
    def create_recipe(
        db: Session,
        user: AuthenticatedUser,
        title: str,
        ingredients: Union[str, List[str]],
        instructions: str,
        is_public: bool = False,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a recipe linked to the authenticated user."""
        if not title or not title.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Title cannot be empty"
            )
        if not instructions or not instructions.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Instructions cannot be empty"
            )

        recipe = Recipe(
            author_id=user.id,
            title=title.strip(),
            ingredients=serialize_ingredients(ingredients),
            instructions=instructions.strip(),
            is_public=bool(is_public)
        )
        db.add(recipe)
        db.commit()
        db.refresh(recipe)

        audit_service.record_event(
            db=db,
            event_type="RECIPE_CREATED",
            username=user.sub,
            ip_address=ip_address,
            details=f"Recipe '{recipe.title}' (id: {recipe.id}, is_public: {recipe.is_public}) created by user {user.id}"
        )

        return recipe_to_dict(recipe)

    @staticmethod
    def get_recipes_for_user(db: Session, user: AuthenticatedUser) -> List[Dict[str, Any]]:
        """
        Retrieves recipes based on RBAC rules:
        - All roles ('user', 'curator', 'admin') see all public recipes + their own private recipes.
        - Other users' private recipes remain strictly hidden.
        """
        recipes = (
            db.query(Recipe)
            .filter(
                or_(
                    Recipe.is_public == True,
                    Recipe.author_id == user.id
                )
            )
            .order_by(Recipe.created_at.desc())
            .all()
        )
        return [recipe_to_dict(r) for r in recipes]

    @staticmethod
    def get_recipe_by_id(db: Session, recipe_id: str, user: AuthenticatedUser) -> Dict[str, Any]:
        """
        Retrieves a single recipe:
        - Visible if public or if current user is author.
        - Returns 404 if not found or if private recipe of another user (obscuring existence).
        """
        recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if not recipe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipe not found"
            )

        # Resource isolation
        if not recipe.is_public and recipe.author_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipe not found"
            )

        return recipe_to_dict(recipe)

    @staticmethod
    def update_recipe(
        db: Session,
        recipe_id: str,
        user: AuthenticatedUser,
        title: Optional[str] = None,
        ingredients: Optional[Union[str, List[str]]] = None,
        instructions: Optional[str] = None,
        is_public: Optional[bool] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Updates a recipe:
        - Author can update their own recipe (public or private).
        - Curators and Admins can update any public recipe.
        - Private recipes of other users cannot be updated by anyone else (403 Forbidden).
        """
        recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if not recipe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipe not found"
            )

        # Check authorization
        is_owner = recipe.author_id == user.id
        is_privileged_public = recipe.is_public and user.role in ("curator", "admin")

        if not (is_owner or is_privileged_public):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Insufficient permissions to modify this recipe"
            )

        if title is not None:
            recipe.title = title.strip()
        if ingredients is not None:
            recipe.ingredients = serialize_ingredients(ingredients)
        if instructions is not None:
            recipe.instructions = instructions.strip()
        if is_public is not None:
            recipe.is_public = bool(is_public)

        db.commit()
        db.refresh(recipe)

        audit_service.record_event(
            db=db,
            event_type="RECIPE_UPDATED",
            username=user.sub,
            ip_address=ip_address,
            details=f"Recipe {recipe.id} updated by {user.role} {user.id}"
        )

        return recipe_to_dict(recipe)

    @staticmethod
    def delete_recipe(
        db: Session,
        recipe_id: str,
        user: AuthenticatedUser,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Deletes a recipe:
        - User role: Can only delete if author_id == user.id.
        - Curator or Admin: Can delete if author_id == user.id OR if recipe.is_public == True.
        - Attempting to delete another user's private recipe raises 403 Forbidden.
        """
        recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if not recipe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipe not found"
            )

        is_owner = recipe.author_id == user.id
        is_privileged_public = recipe.is_public and user.role in ("curator", "admin")

        if not (is_owner or is_privileged_public):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Insufficient permissions to delete this recipe"
            )

        db.delete(recipe)
        db.commit()

        audit_service.record_event(
            db=db,
            event_type="RECIPE_DELETED",
            username=user.sub,
            ip_address=ip_address,
            details=f"Recipe {recipe_id} deleted by {user.role} {user.id}"
        )

        return {"message": "Recipe deleted successfully"}


recipe_service = RecipeService()
