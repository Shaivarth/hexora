from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.routers import dashboard, history, reports, scan

app = FastAPI(
    title=f"{settings.APP_NAME} API",
    description="AI-assisted static malware analysis for SOC analysts. "
                 "Performs hashing, entropy, signature detection, and heuristic "
                 "risk scoring only — uploaded files are never executed.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_gate(request: Request, call_next):
    """Optional, off-by-default API key check for write endpoints. See README
    for enabling this in production deployments fronted by a reverse proxy."""
    if (
        settings.API_KEY_ENABLED
        and request.url.path.startswith("/api/")
        and request.method in ("POST", "DELETE", "PUT", "PATCH")
    ):
        provided = request.headers.get("X-API-Key", "")
        if provided != settings.API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key."})
    return await call_next(request)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": settings.APP_NAME, "environment": settings.ENVIRONMENT}


app.include_router(scan.router)
app.include_router(history.router)
app.include_router(dashboard.router)
app.include_router(reports.router)

# Frontend (static SPA-ish multi-page site) is served from the same process
# so the whole app is a single deployable unit. Mounted last so /api/* keeps
# priority over the catch-all static handler.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
