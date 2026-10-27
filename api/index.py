import os
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from application.config import Settings
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

# Vercel Serverless runs without local Linux Docker daemon
runtime = UnavailableRuntime()
app = create_app(settings=settings, runtime=runtime)

# Enable CORS for browser / external dashboard requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Provide fallback root response if static frontend is not present
has_root = any(getattr(route, "path", None) == "/" for route in app.routes)
if not has_root:
    @app.get("/", include_in_schema=False)
    def root():
        return {
            "name": "AgentGuard API",
            "version": "0.2.0",
            "status": "ready",
            "endpoints": {
                "health": "/api/v1/health",
                "tasks": "/api/v1/tasks",
                "platform": "/api/v1/platform",
            },
        }
