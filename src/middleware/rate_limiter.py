import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException, status
from src.config.settings import settings


class InMemoryLoginRateLimiter:
    """
    Sliding window rate limiter specifically for failed login attempts.
    Tracks failed attempts by client IP address and username within a rolling window.
    Default: Maximum of 5 failed login attempts per 5-minute window (300 seconds).
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        # Maps key -> list of failure timestamps
        self._ip_failures: Dict[str, List[float]] = defaultdict(list)
        self._user_failures: Dict[str, List[float]] = defaultdict(list)

    def _cleanup_old_attempts(self, timestamps: List[float], now: float) -> List[float]:
        threshold = now - self.window_seconds
        return [ts for ts in timestamps if ts > threshold]

    def get_client_ip(self, request: Request) -> str:
        # Check forwarded headers first (for reverse proxies / Docker)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        client = request.client
        return client.host if client else "127.0.0.1"

    def is_rate_limited(self, ip: str, username: str) -> Tuple[bool, int]:
        """
        Checks if the client IP or username has exceeded the allowed failed attempts.
        Returns (is_limited, retry_after_seconds).
        """
        now = time.time()
        # Clean up expired timestamps
        self._ip_failures[ip] = self._cleanup_old_attempts(self._ip_failures[ip], now)
        if username:
            self._user_failures[username] = self._cleanup_old_attempts(self._user_failures[username], now)

        ip_count = len(self._ip_failures[ip])
        user_count = len(self._user_failures[username]) if username else 0

        if ip_count >= self.max_attempts or user_count >= self.max_attempts:
            # Calculate time remaining until oldest failure in the active window expires
            oldest_ts = now
            if ip_count >= self.max_attempts and self._ip_failures[ip]:
                oldest_ts = min(oldest_ts, self._ip_failures[ip][0])
            if user_count >= self.max_attempts and self._user_failures[username]:
                oldest_ts = min(oldest_ts, self._user_failures[username][0])
            retry_after = max(1, int(self.window_seconds - (now - oldest_ts)))
            return True, retry_after

        return False, 0

    def record_failure(self, ip: str, username: str):
        """Records a failed login attempt for the given IP and username."""
        now = time.time()
        self._ip_failures[ip].append(now)
        if username:
            self._user_failures[username].append(now)

    def record_success(self, ip: str, username: str):
        """Optionally clear or retain on success; here we clear to reward valid credentials."""
        # When a user successfully authenticates, their user lock clears
        if username in self._user_failures:
            self._user_failures[username] = []

    def reset_all(self):
        """Used in test suites to reset limiter state between runs."""
        self._ip_failures.clear()
        self._user_failures.clear()


login_rate_limiter = InMemoryLoginRateLimiter(
    max_attempts=settings.RATE_LIMIT_FAILED_LOGINS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)
