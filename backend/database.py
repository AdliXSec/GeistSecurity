import os
import aiosqlite
import json
from typing import Optional, List, Dict, Any
from backend.config import settings

async def _execute_schema(db: aiosqlite.Connection):
    try:
        await db.execute("PRAGMA journal_mode = DELETE;")
        await db.execute("PRAGMA synchronous = NORMAL;")
    except Exception:
        pass

    await db.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            session_id TEXT PRIMARY KEY,
            user_id TEXT,
            project_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            target_url TEXT,
            github_repo_url TEXT,
            branch TEXT DEFAULT 'main',
            score INTEGER DEFAULT 0,
            grade TEXT DEFAULT 'D',
            grade_label TEXT DEFAULT '',
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            report_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)

    # Migration: ensure user_id column exists if table was already created
    try:
        async with db.execute("PRAGMA table_info(audits)") as cursor:
            columns = [row[1] for row in await cursor.fetchall()]
            if "user_id" not in columns:
                await db.execute("ALTER TABLE audits ADD COLUMN user_id TEXT;")
    except Exception:
        pass

    try:
        await db.execute("CREATE INDEX IF NOT EXISTS idx_audits_user_id ON audits (user_id);")
    except Exception:
        pass

    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            created_at TEXT NOT NULL
        );
    """)
    await db.commit()

    try:
        async with db.execute("SELECT COUNT(*) FROM audits") as cursor:
            row = await cursor.fetchone()
            if row and row[0] == 0:
                now_iso = "2026-10-24T02:15:22Z"
                await db.execute("""
                    INSERT INTO audits (
                        session_id, user_id, project_name, mode, status,
                        target_url, github_repo_url, branch,
                        score, grade, grade_label, critical_count, high_count, duration_ms,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "demo-fintech", None, "Fintech Payment Core", "HYBRID", "COMPLETED",
                    "https://demo-fintech.auraglass.io", "https://github.com/auraglass/fintech-core", "main",
                    38, "D", "Grade D (38/100)", 3, 3, 24200,
                    now_iso, now_iso
                ))
                await db.commit()
    except Exception:
        pass

async def init_db():
    target_path = settings.DATABASE_PATH
    try:
        db_dir = os.path.dirname(target_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        async with aiosqlite.connect(target_path) as db:
            await _execute_schema(db)
    except Exception:
        if target_path != "/tmp/secaudit.db":
            settings.DATABASE_PATH = "/tmp/secaudit.db"
            async with aiosqlite.connect("/tmp/secaudit.db") as db:
                await _execute_schema(db)
        else:
            raise

async def get_db():
    await init_db()
    return aiosqlite.connect(settings.DATABASE_PATH)

async def save_audit(
    session_id: str,
    project_name: str,
    mode: str,
    status: str,
    target_url: Optional[str],
    github_repo_url: Optional[str],
    branch: str,
    created_at: str,
    updated_at: str,
    score: int = 0,
    grade: str = "D",
    grade_label: str = "",
    critical_count: int = 0,
    high_count: int = 0,
    duration_ms: int = 0,
    report_json: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
):
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        report_str = json.dumps(report_json) if report_json else None
        await db.execute(
            """
            INSERT INTO audits (
                session_id, user_id, project_name, mode, status, target_url, github_repo_url,
                branch, score, grade, grade_label, critical_count, high_count,
                duration_ms, report_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                user_id = COALESCE(excluded.user_id, audits.user_id),
                status = excluded.status,
                score = excluded.score,
                grade = excluded.grade,
                grade_label = excluded.grade_label,
                critical_count = excluded.critical_count,
                high_count = excluded.high_count,
                duration_ms = excluded.duration_ms,
                report_json = excluded.report_json,
                updated_at = excluded.updated_at
            """,
            (
                session_id, user_id, project_name, mode, status, target_url, github_repo_url,
                branch, score, grade, grade_label, critical_count, high_count,
                duration_ms, report_str, created_at, updated_at
            ),
        )
        await db.commit()

async def get_audit(session_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id:
            query = "SELECT * FROM audits WHERE session_id = ? AND (user_id = ? OR user_id IS NULL)"
            params = (session_id, user_id)
        else:
            query = "SELECT * FROM audits WHERE session_id = ?"
            params = (session_id,)
        async with db.execute(query, params) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("report_json"):
                data["report"] = json.loads(data["report_json"])
            return data

async def list_audits(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id:
            query = (
                "SELECT session_id, user_id, project_name, mode, status, score, grade, grade_label, "
                "critical_count, high_count, target_url, github_repo_url, branch, duration_ms, created_at "
                "FROM audits WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
            )
            params = (user_id, limit)
        else:
            query = (
                "SELECT session_id, user_id, project_name, mode, status, score, grade, grade_label, "
                "critical_count, high_count, target_url, github_repo_url, branch, duration_ms, created_at "
                "FROM audits ORDER BY created_at DESC LIMIT ?"
            )
            params = (limit,)
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

async def delete_audit(session_id: str, user_id: Optional[str] = None) -> bool:
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        if user_id:
            cursor = await db.execute("DELETE FROM audits WHERE session_id = ? AND user_id = ?", (session_id, user_id))
        else:
            cursor = await db.execute("DELETE FROM audits WHERE session_id = ?", (session_id,))
        await db.commit()
        return cursor.rowcount > 0

async def delete_audits_batch(session_ids: list[str], user_id: Optional[str] = None) -> int:
    if not session_ids:
        return 0
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        placeholders = ",".join("?" for _ in session_ids)
        if user_id:
            cursor = await db.execute(
                f"DELETE FROM audits WHERE session_id IN ({placeholders}) AND user_id = ?",
                (*session_ids, user_id),
            )
        else:
            cursor = await db.execute(
                f"DELETE FROM audits WHERE session_id IN ({placeholders})",
                session_ids,
            )
        await db.commit()
        return cursor.rowcount

# ====================================================================
#  User Database Operations
# ====================================================================

async def create_user(
    user_id: str,
    username: str,
    email: str,
    password_hash: str,
    full_name: Optional[str],
    created_at: str,
) -> Dict[str, Any]:
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        await db.execute(
            """
            INSERT INTO users (id, username, email, password_hash, full_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username.lower().strip(), email.lower().strip(), password_hash, full_name, created_at),
        )
        await db.commit()
    return {
        "id": user_id,
        "username": username.lower().strip(),
        "email": email.lower().strip(),
        "full_name": full_name,
        "created_at": created_at,
    }

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_user_by_username_or_email(identifier: str) -> Optional[Dict[str, Any]]:
    await init_db()
    clean_id = identifier.lower().strip()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (clean_id, clean_id),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None
