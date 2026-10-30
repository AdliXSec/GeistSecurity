import os
import sys
import types
from pathlib import Path
from contextlib import asynccontextmanager

# Ensure root directory is in sys.path and virtual 'backend' package exists
_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent

for p in [str(_ROOT_DIR), str(_CURRENT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

if "backend" not in sys.modules:
    pkg = types.ModuleType("backend")
    pkg.__path__ = [str(_CURRENT_DIR)]
    pkg.__file__ = str(_CURRENT_DIR / "__init__.py")
    sys.modules["backend"] = pkg

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from backend.config import settings
from backend.database import init_db
from backend.routers import audits, auth, presets

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Inisialisasi Database SQLite dengan proteksi serverless error handling
    try:
        await init_db()
    except Exception as e:
        import logging
        logging.getLogger("uvicorn.error").error(f"Failed to initialize database during startup: {e}")
    yield
    # Shutdown

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Autonomous Whitebox & Blackbox Web Security Audit Platform API conforming to PRD.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    import traceback
    err_tb = traceback.format_exc()
    print(f"[ERROR] Unhandled exception on {request.method} {request.url.path}: {err_tb}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": f"{type(exc).__name__}: {str(exc)}",
            "path": request.url.path,
        },
    )

@app.middleware("http")
async def normalize_double_api_middleware(request: Request, call_next):
    # Fix accidental double /api/api prefix if frontend environment variable has /api appended
    path = request.scope.get("path", "")
    if path.startswith("/api/api/"):
        request.scope["path"] = path[4:]
    return await call_next(request)

# Include Routers
app.include_router(audits.router)
app.include_router(auth.router)
app.include_router(presets.router)
app.include_router(presets.legacy_router)

@app.get("/api", tags=["API Root"])
@app.get("/api/", tags=["API Root"])
async def api_root():
    return {
        "status": "online",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "docs_url": "/api/docs",
        "health_url": "/api/v1/health"
    }

@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "mode": "demo" if settings.DEMO_MODE else "production"
    }

# SPA Frontend Serving jika dist sudah di-build (berguna untuk Docker & Production)
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if (FRONTEND_DIST / "index.html").exists():
    if (FRONTEND_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
        target_file = FRONTEND_DIST / full_path
        if target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
else:
    @app.get("/", tags=["Root"])
    async def root():
        return {
            "message": f"Welcome to {settings.APP_NAME}",
            "docs_url": "/api/docs",
            "health_url": "/api/v1/health"
        }
