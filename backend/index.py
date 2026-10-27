"""
Vercel Serverless Function entrypoint for SecAudit Backend.
"""
import sys
from pathlib import Path

# Ensure root directory and backend directory are in sys.path
_ROOT_DIR = Path(__file__).resolve().parent.parent
_BACKEND_DIR = Path(__file__).resolve().parent

for p in [str(_ROOT_DIR), str(_BACKEND_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.main import app

# Export ASGI application instance for Vercel
__all__ = ["app"]
