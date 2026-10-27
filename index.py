"""
Root ASGI entrypoint for SecAudit Backend (Vercel Serverless Function fallback).
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.main import app

__all__ = ["app"]
