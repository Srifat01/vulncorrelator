"""Authentication, authorization, rate limiting and request hygiene.

Roles: `admin` (API_KEY) may do everything; `reader` (READONLY_API_KEY) may only GET.
Secure default: with no key configured the API answers 503 until one is set (or AUTH_DISABLED=true is set
explicitly for local development).
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, Response, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings
from app.services.audit import audit
from app.services.ratelimit import get_limiter

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW = 20, 60


@dataclass(frozen=True)
class Principal:
    role: str  # admin | reader
    actor: str  # "key:<8 hex of sha256(key)>" - safe to log


def _actor(key: str) -> str:
    return "key:" + hashlib.sha256(key.encode()).hexdigest()[:8]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _category(request: Request) -> tuple[str, int]:
    s, path = get_settings(), request.url.path
    if path.startswith("/ingest"):
        return "ingest", s.rate_limit_ingest_per_min
    if request.method not in SAFE_METHODS and (path.startswith("/analysis") or path.startswith("/intel")):
        return "analysis", s.rate_limit_analysis_per_min
    return "default", s.rate_limit_default_per_min


def authorize(request: Request, response: Response, x_api_key: str | None = Header(default=None)) -> Principal:
    """Router-level dependency: authenticate, authorize by HTTP method, then rate-limit."""
    s, limiter, ip = get_settings(), get_limiter(), client_ip(request)

    if s.auth_disabled:
        principal = Principal("admin", "auth-disabled")
    else:
        keys = [(k, r) for k, r in ((s.api_key, "admin"), (s.readonly_api_key, "reader")) if k]
        if not keys:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "authentication is not configured: set API_KEY (or AUTH_DISABLED=true for local development)",
            )
        # Brute-force guard: too many recent failures from this address => 429 before comparing anything.
        if s.rate_limit_enabled and limiter.count(f"authfail:{ip}") >= AUTH_FAIL_LIMIT:
            raise HTTPException(429, "too many failed authentication attempts", headers={"Retry-After": "60"})
        principal = None
        if x_api_key:
            for key, role in keys:
                if secrets.compare_digest(x_api_key.encode(), key.encode()):
                    principal = Principal(role, _actor(key))
                    break
        if principal is None:
            limiter.hit(f"authfail:{ip}", AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW)
            audit(
                actor="anonymous",
                role="none",
                action="auth",
                status="denied",
                resource=request.url.path,
                client_ip=ip,
                request_id=request_id(request),
            )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")

    if request.method not in SAFE_METHODS and principal.role != "admin":
        audit(
            actor=principal.actor,
            role=principal.role,
            action="authz",
            status="denied",
            resource=f"{request.method} {request.url.path}",
            client_ip=ip,
            request_id=request_id(request),
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this API key is read-only")

    if s.rate_limit_enabled:
        category, limit = _category(request)
        allowed, remaining, reset = limiter.hit(f"{category}:{principal.actor}", limit, 60)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        if not allowed:
            audit(
                actor=principal.actor,
                role=principal.role,
                action="rate_limited",
                status="denied",
                resource=f"{category} {request.url.path}",
                client_ip=ip,
                request_id=request_id(request),
            )
            raise HTTPException(
                429,
                f"rate limit exceeded ({limit}/min for {category})",
                headers={"Retry-After": str(reset), "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0"},
            )
    request.state.principal = principal
    return principal


def audit_action(
    request: Request,
    principal: Principal,
    action: str,
    resource: str | None = None,
    status_: str = "ok",
    detail: dict | None = None,
) -> None:
    audit(
        actor=principal.actor,
        role=principal.role,
        action=action,
        resource=resource,
        status=status_,
        client_ip=client_ip(request),
        request_id=request_id(request),
        detail=detail,
    )


class _BodyTooLarge(Exception):
    pass


class RequestContextMiddleware:
    """Assigns a request id and rejects oversized bodies before they are buffered into memory."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = rid
        limit = get_settings().max_request_body_mb * 1024 * 1024

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).append((b"x-request-id", rid.encode()))
            await send(message)

        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            await self._too_large(send_with_id)
            return

        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:  # chunked bodies without a Content-Length
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, counting_receive, send_with_id)
        except _BodyTooLarge:
            await self._too_large(send_with_id)

    @staticmethod
    async def _too_large(send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


def require_admin(request: Request) -> Principal:
    """Extra guard for admin-only reads (e.g. the audit log). Runs after `authorize`, which sets the principal."""
    principal: Principal = request.state.principal
    if principal.role != "admin":
        audit_action(request, principal, "authz", f"{request.method} {request.url.path}", status_="denied")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return principal
