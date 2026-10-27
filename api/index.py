import os
from pathlib import Path
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from application.config import Settings
from application.store import Store
from application.authority import Authority
from application.api import create_app
from application.runtime_adapter import UnavailableRuntime

# Ensure /tmp directory exists for SQLite storage in serverless environments
db_dir = Path("/tmp/agentguard")
db_dir.mkdir(parents=True, exist_ok=True)
db_path = db_dir / "agentguard.sqlite3"

# Minimum 32-character keys required by AgentGuard settings validation
owner_token = os.environ.get("AG_OWNER_TOKEN", "agentguard_owner_token_32chars_min_secret!")
runtime_token = os.environ.get("AG_RUNTIME_TOKEN", "agentguard_runtime_token_32chars_min_sec!")
integrity_key = os.environ.get("AG_INTEGRITY_KEY", "agentguard_integrity_key_32chars_min_sec!")

settings = Settings(
    database=Path(os.environ.get("AG_DATABASE_PATH", str(db_path))),
    owner_token=owner_token,
    runtime_token=runtime_token,
    integrity_key=integrity_key,
)

# Auto-seed initial demo task FIN-001 if freshly initialized
try:
    _store = Store(settings.database, settings.integrity_key)
    _auth = Authority(_store)
    try:
        _auth.record("FIN-001")
    except KeyError:
        _auth.create("synthetic-finance-owner", "FIN-001")
except Exception:
    pass

# Vercel Serverless runs without local Linux Docker daemon
runtime = UnavailableRuntime()
app = create_app(settings=settings, runtime=runtime)

# Enable CORS for cross-origin or local requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to restore original request path from Vercel rewrite headers
@app.middleware("http")
async def restore_vercel_path(request: Request, call_next):
    matched = (
        request.headers.get("x-matched-path")
        or request.headers.get("x-invoke-path")
        or request.headers.get("x-real-path")
    )
    if matched:
        request.scope["path"] = matched.split("?")[0]
    return await call_next(request)

# Mount SPA index fallback if dist directory is present
dist = Path(__file__).resolve().parent.parent / "dashboard" / "application" / "dist"
if dist.exists():
    @app.get("/index.html", include_in_schema=False)
    def index_html():
        return FileResponse(dist / "index.html")

    @app.exception_handler(404)
    async def spa_fallback(request: Request, exc):
        if request.method == "GET" and not request.url.path.startswith(("/api/", "/internal/", "/assets/")):
            return FileResponse(dist / "index.html")
        return JSONResponse({"detail": "Not Found"}, status_code=404)
