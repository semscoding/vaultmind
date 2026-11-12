"""
VaultMind v2 Entrypoint (`main.py`).
Mounts the `apis` router and serves the `frontend` static dashboard on loopback 127.0.0.1:8000.
TrustedHostMiddleware rejects any Host header other than loopback (DNS-rebinding guard).
"""

import os
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from apis.routes import router as api_router

app = FastAPI(title="VaultMind v2: Zero-Trust AI Agent Pipeline")
# "testserver" is the Host used by FastAPI's TestClient.
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
)
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
