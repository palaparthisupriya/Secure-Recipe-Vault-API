import os
import re
from typing import Union
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_duration(val: Union[str, int]) -> int:
    """Parse duration string (e.g., '15m', '7d', '10s') or int into seconds."""
    if isinstance(val, int):
        return val
    val = val.strip()
    match = re.match(r"^(\d+)([smhd]?)$", val, re.IGNORECASE)
    if not match:
        try:
            return int(val)
        except ValueError:
            return 900  # Default 15 minutes
    num, unit = match.groups()
    num = int(num)
    unit = unit.lower()
    if unit == "s" or unit == "":
        return num
    elif unit == "m":
        return num * 60
    elif unit == "h":
        return num * 3600
    elif unit == "d":
        return num * 86400
    return num


class Settings(BaseSettings):
    PORT: int = 3000
    HOST: str = "0.0.0.0"
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite:///./recipe_vault.db"

    JWT_ACCESS_SECRET: str = "super_secret_jwt_access_signing_key_recipe_vault_2026_secure"
    JWT_REFRESH_SECRET: str = "super_secret_jwt_refresh_signing_key_recipe_vault_2026_secure"
    JWT_ACCESS_EXPIRES_IN: str = "15m"
    JWT_REFRESH_EXPIRES_IN: str = "7d"

    RATE_LIMIT_FAILED_LOGINS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 300

    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "Strict"

    @property
    def access_token_expire_seconds(self) -> int:
        return parse_duration(self.JWT_ACCESS_EXPIRES_IN)

    @property
    def refresh_token_expire_seconds(self) -> int:
        return parse_duration(self.JWT_REFRESH_EXPIRES_IN)

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
