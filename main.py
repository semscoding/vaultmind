"""
VaultMind v2 Entrypoint (`main.py`).
Mounts the `apis` router and serves the `frontend` static dashboard on loopback 127.0.0.1:8000.
TrustedHostMiddleware rejects any Host header other than loopback (DNS-rebinding guard).
"""

import os
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from apis.routes import router as api_router

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "testserver"}
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

app = FastAPI(title="VaultMind v2: Zero-Trust AI Agent Pipeline")
# "testserver" is the Host used by FastAPI's TestClient.
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=sorted(ALLOWED_LOOPBACK_HOSTS)
)


@app.middleware("http")
async def reject_cross_origin_mutations(request: Request, call_next):
    """Block cross-site / cross-origin browser POSTs to loopback endpoints (CSRF / simple-POST guard)."""
    if request.method.upper() in STATE_CHANGING_METHODS:
        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sec_fetch_site == "cross-site":
            return JSONResponse(
                status_code=403,
                content={"detail": "Cross-site requests to the loopback API are forbidden."},
            )
        origin = (request.headers.get("origin") or "").strip()
        if origin:
            try:
                parsed = urlparse(origin)
                scheme = parsed.scheme
                hostname = (parsed.hostname or "").lower()
                _ = parsed.port  # Validates 0 <= port <= 65535 (raises ValueError otherwise)
            except ValueError:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Malformed Origin header in request to loopback API."},
                )
            has_extra_parts = bool(
                parsed.username or parsed.password or parsed.path or parsed.params or parsed.query or parsed.fragment
            )
            # Same-origin means the Origin's host:port equals the Host header of this request, so
            # another local app on a different port (http://localhost:3000) is rejected too.
            same_host_port = parsed.netloc.lower() == (request.headers.get("host") or "").strip().lower()
            if (
                scheme not in ("http", "https")
                or hostname not in ALLOWED_LOOPBACK_HOSTS
                or has_extra_parts
                or not same_host_port
            ):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-origin requests to the loopback API are forbidden."},
                )
    return await call_next(request)


app.include_router(api_router)

root_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(root_dir, "frontend", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def serve_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"message": "VaultMind v2 API running."})


if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 64)
    print("🛡️  VAULTMIND v2: Native C Enclave + 2048-bit Feldman VSS + Paillier PHE + RLWE-BFV (leveled, depth 1)")
    print("📡  Loopback Dashboard: http://127.0.0.1:8000")
    print("=" * 64 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
