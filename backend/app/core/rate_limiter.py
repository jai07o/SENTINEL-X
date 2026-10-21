import time
from typing import Dict, List, Tuple
from collections import defaultdict
from fastapi import Request, HTTPException, status


class BruteForceProtector:
    """
    Adaptive In-Memory Brute-Force & Credential Stuffing Defense Shield.
    Tracks authentication failures across IP addresses and usernames.
    Engages automated temporary lockouts upon exceeding failure thresholds.
    """
    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
    ):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        
        # identifier -> list of failure timestamps
        self._failures: Dict[str, List[float]] = defaultdict(list)
        # identifier -> lockout expiration timestamp
        self._lockouts: Dict[str, float] = {}

    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if an IP or account is currently locked out.
        Returns: (is_locked: bool, seconds_remaining: int)
        """
        now = time.time()
        lockout_expiry = self._lockouts.get(identifier)
        if lockout_expiry:
            if now < lockout_expiry:
                remaining = int(lockout_expiry - now)
                return True, max(1, remaining)
            else:
                # Lockout expired, clean up
                del self._lockouts[identifier]
                self._failures.pop(identifier, None)

        return False, 0

    def record_failure(self, identifier: str) -> Tuple[bool, int, int]:
        """
        Record a failed authentication attempt.
        Returns: (is_now_locked: bool, remaining_attempts: int, lockout_seconds: int)
        """
        now = time.time()
        
        # Clean older failures outside sliding window
        cutoff = now - self.window_seconds
        recent = [t for t in self._failures[identifier] if t > cutoff]
        recent.append(now)
        self._failures[identifier] = recent

        if len(recent) >= self.max_failures:
            # Trigger lockout
            self._lockouts[identifier] = now + self.lockout_seconds
            return True, 0, self.lockout_seconds

        attempts_left = max(0, self.max_failures - len(recent))
        return False, attempts_left, 0

    def record_success(self, identifier: str) -> None:
        """Reset failures upon verified successful authentication."""
        self._failures.pop(identifier, None)
        self._lockouts.pop(identifier, None)

    def get_stats(self) -> dict:
        """Return real-time anti-brute-force defense metrics."""
        now = time.time()
        active_locks = {
            k: int(v - now) for k, v in self._lockouts.items() if v > now
        }
        return {
            "max_failures_threshold": self.max_failures,
            "window_seconds": self.window_seconds,
            "lockout_duration_seconds": self.lockout_seconds,
            "active_lockouts_count": len(active_locks),
            "locked_entities": list(active_locks.keys()),
        }


class EndpointRateLimiter:
    """
    Sliding Window Token Bucket Rate Limiter for sensitive API endpoints.
    Protects against Denial-of-Service (DoS), CPU starvation, and rapid probing.
    """
    def __init__(self):
        # (ip, endpoint) -> list of request timestamps
        self._requests: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    def check_rate_limit(
        self,
        request: Request,
        endpoint_tag: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        """
        Enforce rate limits. Raises HTTP 429 if rate limit is exceeded.
        """
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        key = (client_ip, endpoint_tag)

        cutoff = now - window_seconds
        recent = [t for t in self._requests[key] if t > cutoff]
        
        if len(recent) >= max_requests:
            retry_after = int(window_seconds - (now - recent[0])) if recent else window_seconds
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit exceeded for endpoint [{endpoint_tag}]. Please back off.",
                    "client_ip": client_ip,
                    "retry_after_seconds": max(1, retry_after),
                },
                headers={"Retry-After": str(max(1, retry_after))},
            )

        recent.append(now)
        self._requests[key] = recent


# Global Singleton Instances
brute_force_protector = BruteForceProtector(
    max_failures=5,
    window_seconds=300,   # 5-minute detection window
    lockout_seconds=900,  # 15-minute defensive lockout
)

rate_limiter = EndpointRateLimiter()
