"""Fixed-window rate limiting. Redis-backed when REDIS_URL is set (shared across API workers), else in-process."""

import threading
import time
from typing import Protocol

import redis

from app.config import get_settings


class Limiter(Protocol):
    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int, int]:
        """Count one request. Returns (allowed, remaining, seconds_until_reset)."""

    def count(self, key: str) -> int: ...


class MemoryLimiter:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}  # key -> (window_end, count)

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int, int]:
        now = self._clock()
        with self._lock:
            end, n = self._windows.get(key, (0.0, 0))
            if now >= end:
                end, n = now + window, 0
            n += 1
            self._windows[key] = (end, n)
            if len(self._windows) > 50_000:  # bound memory: drop expired windows
                self._windows = {k: v for k, v in self._windows.items() if v[0] > now}
            return n <= limit, max(0, limit - n), max(1, int(end - now))

    def count(self, key: str) -> int:
        end, n = self._windows.get(key, (0.0, 0))
        return n if self._clock() < end else 0


class RedisLimiter:
    def __init__(self, client: redis.Redis):
        self.client = client

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int, int]:
        k = f"vc:rl:{key}"
        try:
            pipe = self.client.pipeline()
            pipe.incr(k)
            pipe.expire(k, window, nx=True)  # only set the TTL on the first hit of a window
            pipe.ttl(k)
            n, _, ttl = pipe.execute()
        except redis.RedisError:
            return True, limit, window  # fail open: Redis trouble must not take the API down
        return n <= limit, max(0, limit - n), max(1, ttl)

    def count(self, key: str) -> int:
        try:
            return int(self.client.get(f"vc:rl:{key}") or 0)
        except redis.RedisError:
            return 0


_limiter: Limiter | None = None


def get_limiter() -> Limiter:
    global _limiter
    if _limiter is None:
        url = get_settings().redis_url
        _limiter = RedisLimiter(redis.Redis.from_url(url)) if url else MemoryLimiter()
    return _limiter


def set_limiter(limiter: Limiter | None) -> None:
    global _limiter
    _limiter = limiter
