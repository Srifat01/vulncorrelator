"""Optional Redis cache. Fails open: if Redis is down, requests just skip the cache."""

import json
import logging
from typing import Any

import redis

from app.config import get_settings

log = logging.getLogger(__name__)


class NullCache:
    def get(self, key: str) -> Any | None:
        return None

    def set(self, key: str, value: Any) -> None:
        pass

    def invalidate(self) -> None:
        pass


class RedisCache:
    """Keys embed a version counter; bumping it invalidates everything in O(1)."""

    VERSION_KEY = "vc:cache:version"

    def __init__(self, client: redis.Redis, ttl: int):
        self.client, self.ttl = client, ttl

    def _key(self, key: str) -> str:
        return f"vc:cache:{self.client.get(self.VERSION_KEY) or 0}:{key}"

    def get(self, key: str) -> Any | None:
        try:
            raw = self.client.get(self._key(key))
            return json.loads(raw) if raw else None
        except redis.RedisError:
            log.warning("cache read failed", exc_info=True)
            return None

    def set(self, key: str, value: Any) -> None:
        try:
            self.client.set(self._key(key), json.dumps(value), ex=self.ttl)
        except redis.RedisError:
            log.warning("cache write failed", exc_info=True)

    def invalidate(self) -> None:
        try:
            self.client.incr(self.VERSION_KEY)
        except redis.RedisError:
            log.warning("cache invalidation failed", exc_info=True)


_cache: NullCache | RedisCache | None = None


def get_cache() -> NullCache | RedisCache:
    global _cache
    if _cache is None:
        s = get_settings()
        _cache = (
            RedisCache(redis.Redis.from_url(s.redis_url, decode_responses=True), s.cache_ttl_seconds)
            if s.redis_url
            else NullCache()
        )
    return _cache


def set_cache(cache: NullCache | RedisCache | None) -> None:
    global _cache
    _cache = cache
