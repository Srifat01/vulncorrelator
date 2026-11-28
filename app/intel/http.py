"""Resilient HTTP for threat-intel feeds: timeouts, bounded retries with back-off + jitter, Retry-After,
and client-side rate limiting. Sleep/clock/transport are injectable so behaviour is testable without a network."""

import logging
import random
import time
from collections import deque
from collections.abc import Callable

import httpx

log = logging.getLogger(__name__)
RETRYABLE = (429, 500, 502, 503, 504)


class IntelError(Exception):
    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status, self.retryable = status, retryable


class SlidingWindowLimiter:
    """At most `max_calls` per `per_seconds`; blocks (via `sleep`) instead of letting the upstream reject us."""

    def __init__(self, max_calls: int, per_seconds: float, clock=time.monotonic, sleep=time.sleep):
        self.max_calls, self.per, self._clock, self._sleep = max_calls, per_seconds, clock, sleep
        self._calls: deque[float] = deque()

    def acquire(self) -> None:
        now = self._clock()
        while self._calls and now - self._calls[0] >= self.per:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            wait = self.per - (now - self._calls[0])
            self._sleep(max(0.0, wait))
            now = self._clock()
            while self._calls and now - self._calls[0] >= self.per:
                self._calls.popleft()
        self._calls.append(now)


class ResilientClient:
    def __init__(
        self,
        *,
        timeout: float = 20.0,
        max_retries: int = 4,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
        limiter: SlidingWindowLimiter | None = None,
        user_agent: str = "vulncorrelator/2.0 (+threat-intel sync)",
    ):
        self._http = httpx.Client(timeout=timeout, transport=transport, headers={"User-Agent": user_agent})
        self.max_retries, self._sleep, self._rng, self.limiter = max_retries, sleep, rng, limiter
        self.requests_made = 0

    def close(self) -> None:
        self._http.close()

    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        retry_on: tuple[int, ...] = RETRYABLE,
        ok: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        last = "no attempt made"
        for attempt in range(self.max_retries + 1):
            if self.limiter:
                self.limiter.acquire()
            self.requests_made += 1
            try:
                resp = self._http.get(url, params=params, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last, delay = f"{type(exc).__name__}: {exc}", None
            else:
                if resp.status_code in ok:
                    return resp
                if resp.status_code not in retry_on:
                    raise IntelError(f"HTTP {resp.status_code} from {url}", status=resp.status_code)
                last, delay = f"HTTP {resp.status_code}", self._retry_after(resp)
            if attempt == self.max_retries:
                break
            wait = delay if delay is not None else min(60.0, 2.0**attempt + self._rng())
            log.warning(
                "intel fetch %s failed (%s); retry %d/%d in %.1fs", url, last, attempt + 1, self.max_retries, wait
            )
            self._sleep(wait)
        raise IntelError(f"giving up on {url} after {self.max_retries + 1} attempts: {last}", retryable=True)

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float | None:
        raw = resp.headers.get("Retry-After")
        if raw and raw.isdigit():
            return min(float(raw), 120.0)  # honour the server, but never sleep unboundedly
        return None
