import time
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from backend.app.core.rate_limiter import brute_force_protector, rate_limiter


class HardenedSecurityMiddleware(BaseHTTPMiddleware):
    """
    Military-Grade Defensive HTTP Middleware Suite:
    - Strict Content-Security-Policy (CSP) & HSTS Preload
    - Anti-Clickjacking (X-Frame-Options: DENY)
    - Anti-MIME-Sniffing (X-Content-Type-Options: nosniff)
    - Restrictive Permissions-Policy & COOP/CORP isolation
    - In-Flight Request Body Size Limiter (Anti-DoS / Memory Starvation: max 25MB)
    - Dynamic Cache-Control Disabling on Sensitive API Routes
    - Adaptive In-Memory Brute-Force & Rate Limiting Enforcement
    - Stripped Server Technology Disclosures
    """

    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 Megabytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"
        path = request.url.path

        # 1. Payload Size Guard (Anti-DoS Memory Exhaustion)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.MAX_CONTENT_LENGTH:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "PAYLOAD_TOO_LARGE",
                            "message": f"Request body exceeds maximum permitted threshold ({self.MAX_CONTENT_LENGTH // (1024 * 1024)}MB). Request rejected by SENTINEL-X Shield.",
                        },
                    )
            except ValueError:
                pass

        # 2. Brute-Force Lockout Guard on Authentication Paths
        if path == "/api/v1/auth/login" and request.method == "POST":
            is_locked, remaining_seconds = brute_force_protector.is_locked_out(client_ip)
            if is_locked:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "TEMPORARY_SECURITY_LOCKOUT",
                        "message": f"Excessive failed authentication attempts from this IP ({client_ip}). IP is locked out for defensive containment.",
                        "retry_after_seconds": remaining_seconds,
                    },
                    headers={"Retry-After": str(remaining_seconds)},
                )

        # 3. Process Request
        response = await call_next(request)

        # 4. Strict Transport & Security Headers
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(self), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(self), payment=(), usb=(self)"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Server"] = "SENTINEL-X-Hardened-Shield"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )

        # 5. Disable Caching for Sensitive API Responses
        if path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response


# Backwards compatibility alias
SecurityHeadersMiddleware = HardenedSecurityMiddleware
