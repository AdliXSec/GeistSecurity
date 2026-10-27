"""
Vercel Serverless Function entrypoint for SecAudit Backend.
"""
import sys
import types
from pathlib import Path

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

from backend.main import app

# Export ASGI application instance for Vercel
__all__ = ["app"]
