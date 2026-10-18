import bcrypt


def hash_password(plain_text_password: str, rounds: int = 12) -> str:
    """
    Hashes a plaintext password using bcrypt with standard salt rounds (default: 12).
    Bcrypt automatically generates a unique salt and prepends it to the resulting hash.
    """
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """
    Cryptographically verifies a plaintext password against the stored bcrypt hash.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    try:
        password_bytes = plain_text_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False
