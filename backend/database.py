import os
import aiosqlite
import json
import logging
import httpx
from typing import Optional, List, Dict, Any
from backend.config import settings

logger = logging.getLogger("secaudit.database")

def is_supabase_enabled(ignore_test: bool = False) -> bool:
    """Memeriksa apakah konfigurasi Supabase (URL dan API Key) aktif.
    Dinonaktifkan saat unit test pytest berjalan untuk mencegah polusi data test ke cloud database.
    """
    if not ignore_test and "PYTEST_CURRENT_TEST" in os.environ:
        return False
    return bool(settings.SUPABASE_URL and settings.SUPABASE_KEY)

def _supabase_headers() -> Dict[str, str]:
    """Header otentikasi standar PostgREST Supabase."""
    return {
        "apikey": settings.SUPABASE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _supabase_url(endpoint: str) -> str:
    """Helper untuk memformat endpoint REST Supabase."""
    base = settings.SUPABASE_URL.rstrip("/")
    if base.endswith("/rest/v1"):
        base = base[:-8].rstrip("/")
    path = endpoint.lstrip("/")
    return f"{base}/rest/v1/{path}"

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

    await db.execute("""
        CREATE TABLE IF NOT EXISTS presets (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            project_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            url TEXT,
            repo TEXT,
            branch TEXT DEFAULT 'main',
            is_demo INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    try:
        await db.execute("CREATE INDEX IF NOT EXISTS idx_presets_user_id ON presets (user_id);")
    except Exception:
        pass
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

    try:
        async with db.execute("SELECT COUNT(*) FROM presets") as cursor:
            row = await cursor.fetchone()
            if row and row[0] == 0:
                now_iso = "2026-10-24T02:15:22Z"
                await db.execute("""
                    INSERT INTO presets (
                        id, user_id, project_name, mode, url, repo, branch, is_demo, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    "demo-fintech", None, "Fintech Payment Gateway (Demo)", "HYBRID",
                    "https://demo-fintech.auraglass.io", "https://github.com/auraglass/fintech-dashboard-api",
                    "main", 1, now_iso, now_iso
                ))
                await db.commit()
    except Exception:
        pass

async def init_db():
    if is_supabase_enabled():
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    _supabase_url("audits?select=session_id&limit=1"),
                    headers=_supabase_headers()
                )
                if res.status_code == 200:
                    rows = res.json()
                    if len(rows) == 0:
                        now_iso = "2026-10-24T02:15:22Z"
                        demo_payload = {
                            "session_id": "demo-fintech",
                            "user_id": None,
                            "project_name": "Fintech Payment Core",
                            "mode": "HYBRID",
                            "status": "COMPLETED",
                            "target_url": "https://demo-fintech.auraglass.io",
                            "github_repo_url": "https://github.com/auraglass/fintech-core",
                            "branch": "main",
                            "score": 38,
                            "grade": "D",
                            "grade_label": "Grade D (38/100)",
                            "critical_count": 3,
                            "high_count": 3,
                            "duration_ms": 24200,
                            "created_at": now_iso,
                            "updated_at": now_iso
                        }
                        await client.post(
                            _supabase_url("audits"),
                            headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                            json=demo_payload
                        )

                    # Inisialisasi seed default demo preset di Supabase jika kosong
                    preset_res = await client.get(
                        _supabase_url("presets?select=id&limit=1"),
                        headers=_supabase_headers()
                    )
                    if preset_res.status_code == 200 and len(preset_res.json()) == 0:
                        demo_preset_payload = {
                            "id": "demo-fintech",
                            "user_id": None,
                            "project_name": "Fintech Payment Gateway (Demo)",
                            "mode": "HYBRID",
                            "url": "https://demo-fintech.auraglass.io",
                            "repo": "https://github.com/auraglass/fintech-dashboard-api",
                            "branch": "main",
                            "is_demo": True,
                            "created_at": "2026-10-24T02:15:22Z",
                            "updated_at": "2026-10-24T02:15:22Z"
                        }
                        await client.post(
                            _supabase_url("presets"),
                            headers={**_supabase_headers(), "Prefer": "resolution=merge-duplicates"},
                            json=demo_preset_payload
                        )

                    logger.info("[Database] Sukses terhubung ke Supabase Cloud Database.")
                    return
                elif res.status_code in [404, 400]:
                    logger.warning(
                        "[Supabase] Tabel belum ditemukan di Supabase. Silakan jalankan supabase_schema.sql di SQL Editor Supabase."
                    )
        except Exception as e:
            logger.error(f"[Supabase] Gagal inisialisasi koneksi Supabase: {e}")
        return

    # Fallback ke SQLite lokal
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
    if is_supabase_enabled():
        report_str = json.dumps(report_json) if report_json else None
        payload = {
            "session_id": session_id,
            "user_id": user_id,
            "project_name": project_name,
            "mode": mode,
            "status": status,
            "target_url": target_url,
            "github_repo_url": github_repo_url,
            "branch": branch,
            "score": score,
            "grade": grade,
            "grade_label": grade_label,
            "critical_count": critical_count,
            "high_count": high_count,
            "duration_ms": duration_ms,
            "report_json": report_str,
            "created_at": created_at,
            "updated_at": updated_at
        }
        headers = {
            **_supabase_headers(),
            "Prefer": "resolution=merge-duplicates"
        }
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                res = await client.post(_supabase_url("audits"), headers=headers, json=payload)
                if res.status_code in [200, 201, 204]:
                    return
                logger.error(f"[Supabase] Gagal menyimpan audit ({res.status_code}): {res.text}")
        except Exception as e:
            logger.error(f"[Supabase] Exception saat menyimpan audit: {e}")

    # Fallback / lokal SQLite
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
    if is_supabase_enabled():
        try:
            query_params = f"session_id=eq.{session_id}"
            if user_id:
                query_params += f"&or=(user_id.eq.{user_id},user_id.is.null)"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(_supabase_url(f"audits?{query_params}"), headers=_supabase_headers())
                if res.status_code == 200:
                    rows = res.json()
                    if rows:
                        data = dict(rows[0])
                        if data.get("report_json"):
                            try:
                                data["report"] = json.loads(data["report_json"])
                            except Exception:
                                data["report"] = None
                        return data
        except Exception as e:
            logger.error(f"[Supabase] Error saat get_audit: {e}")

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
    supabase_records: List[Dict[str, Any]] = []
    if is_supabase_enabled():
        try:
            cols = "session_id,user_id,project_name,mode,status,score,grade,grade_label,critical_count,high_count,target_url,github_repo_url,branch,duration_ms,created_at"
            query_params = f"select={cols}&order=created_at.desc&limit={limit}"
            if user_id:
                query_params += f"&user_id=eq.{user_id}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(_supabase_url(f"audits?{query_params}"), headers=_supabase_headers())
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, list):
                        supabase_records = data
        except Exception as e:
            logger.error(f"[Supabase] Error saat list_audits: {e}")

    await init_db()
    local_records: List[Dict[str, Any]] = []
    try:
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
                local_records = [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"[SQLite] Error saat list_audits: {e}")

    seen_ids = set()
    merged: List[Dict[str, Any]] = []
    for rec in supabase_records:
        sid = rec.get("session_id")
        if sid and sid not in seen_ids:
            seen_ids.add(sid)
            merged.append(rec)
    for rec in local_records:
        sid = rec.get("session_id")
        if sid and sid not in seen_ids:
            seen_ids.add(sid)
            merged.append(rec)
    return merged[:limit]

async def delete_audit(session_id: str, user_id: Optional[str] = None) -> bool:
    if is_supabase_enabled():
        try:
            headers = {**_supabase_headers(), "Prefer": "return=representation"}
            query_params = f"session_id=eq.{session_id}"
            if user_id:
                query_params += f"&user_id=eq.{user_id}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.delete(_supabase_url(f"audits?{query_params}"), headers=headers)
                if res.status_code == 200:
                    deleted = res.json()
                    return len(deleted) > 0
        except Exception as e:
            logger.error(f"[Supabase] Error saat delete_audit: {e}")

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
    if is_supabase_enabled():
        try:
            ids_joined = ",".join(session_ids)
            headers = {**_supabase_headers(), "Prefer": "return=representation"}
            query_params = f"session_id=in.({ids_joined})"
            if user_id:
                query_params += f"&user_id=eq.{user_id}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.delete(_supabase_url(f"audits?{query_params}"), headers=headers)
                if res.status_code == 200:
                    return len(res.json())
        except Exception as e:
            logger.error(f"[Supabase] Error saat delete_audits_batch: {e}")

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
    clean_username = username.lower().strip()
    clean_email = email.lower().strip()

    if is_supabase_enabled():
        payload = {
            "id": user_id,
            "username": clean_username,
            "email": clean_email,
            "password_hash": password_hash,
            "full_name": full_name,
            "created_at": created_at
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    _supabase_url("users"),
                    headers={**_supabase_headers(), "Prefer": "return=representation"},
                    json=payload
                )
                if res.status_code in [200, 201]:
                    return {
                        "id": user_id,
                        "username": clean_username,
                        "email": clean_email,
                        "full_name": full_name,
                        "created_at": created_at,
                    }
                else:
                    logger.error(f"[Supabase] Gagal create_user: {res.status_code} - {res.text}")
        except Exception as e:
            logger.error(f"[Supabase] Exception create_user: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        await db.execute(
            """
            INSERT INTO users (id, username, email, password_hash, full_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, clean_username, clean_email, password_hash, full_name, created_at),
        )
        await db.commit()
    return {
        "id": user_id,
        "username": clean_username,
        "email": clean_email,
        "full_name": full_name,
        "created_at": created_at,
    }

async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    if is_supabase_enabled():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(_supabase_url(f"users?id=eq.{user_id}"), headers=_supabase_headers())
                if res.status_code == 200:
                    rows = res.json()
                    return dict(rows[0]) if rows else None
        except Exception as e:
            logger.error(f"[Supabase] Error get_user_by_id: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_user_by_username_or_email(identifier: str) -> Optional[Dict[str, Any]]:
    clean_id = identifier.lower().strip()
    if is_supabase_enabled():
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(
                    _supabase_url(f"users?or=(username.eq.{clean_id},email.eq.{clean_id})"),
                    headers=_supabase_headers()
                )
                if res.status_code == 200:
                    rows = res.json()
                    return dict(rows[0]) if rows else None
        except Exception as e:
            logger.error(f"[Supabase] Error get_user_by_username_or_email: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (clean_id, clean_id),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

# ====================================================================
#  Preset Database Operations (Supabase & SQLite)
# ====================================================================

async def save_preset(
    preset_id: str,
    project_name: str,
    mode: str,
    url: Optional[str],
    repo: Optional[str],
    branch: str,
    created_at: str,
    updated_at: str,
    user_id: Optional[str] = None,
    is_demo: bool = False,
) -> Dict[str, Any]:
    preset_dict = {
        "id": preset_id,
        "user_id": user_id,
        "project_name": project_name,
        "mode": mode,
        "url": url or "",
        "repo": repo or "",
        "branch": branch or "main",
        "is_demo": bool(is_demo),
        "created_at": created_at,
        "updated_at": updated_at,
    }

    if is_supabase_enabled():
        headers = {
            **_supabase_headers(),
            "Prefer": "resolution=merge-duplicates"
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(_supabase_url("presets"), headers=headers, json=preset_dict)
                if res.status_code not in [200, 201, 204]:
                    logger.error(f"[Supabase] Gagal menyimpan preset ({res.status_code}): {res.text}")
        except Exception as e:
            logger.error(f"[Supabase] Exception saat menyimpan preset: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        await db.execute(
            """
            INSERT INTO presets (
                id, user_id, project_name, mode, url, repo, branch, is_demo, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                user_id = COALESCE(excluded.user_id, presets.user_id),
                project_name = excluded.project_name,
                mode = excluded.mode,
                url = excluded.url,
                repo = excluded.repo,
                branch = excluded.branch,
                is_demo = excluded.is_demo,
                updated_at = excluded.updated_at
            """,
            (
                preset_id, user_id, project_name, mode, url or "", repo or "",
                branch or "main", 1 if is_demo else 0, created_at, updated_at
            ),
        )
        await db.commit()
    return preset_dict

async def list_presets(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    supabase_records: List[Dict[str, Any]] = []
    if is_supabase_enabled():
        try:
            if user_id:
                query_params = f"or=(user_id.eq.{user_id},user_id.is.null)&order=created_at.asc"
            else:
                query_params = "user_id.is.null&order=created_at.asc"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(_supabase_url(f"presets?{query_params}"), headers=_supabase_headers())
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, list):
                        supabase_records = data
        except Exception as e:
            logger.error(f"[Supabase] Error saat list_presets: {e}")

    await init_db()
    local_records: List[Dict[str, Any]] = []
    try:
        async with aiosqlite.connect(settings.DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            if user_id:
                query = "SELECT * FROM presets WHERE user_id = ? OR user_id IS NULL ORDER BY created_at ASC"
                params = (user_id,)
            else:
                query = "SELECT * FROM presets WHERE user_id IS NULL ORDER BY created_at ASC"
                params = ()
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                for r in rows:
                    rec = dict(r)
                    rec["is_demo"] = bool(rec.get("is_demo", 0))
                    local_records.append(rec)
    except Exception as e:
        logger.error(f"[SQLite] Error saat list_presets: {e}")

    seen_ids = set()
    merged: List[Dict[str, Any]] = []
    for rec in supabase_records:
        pid = rec.get("id")
        if pid and pid not in seen_ids:
            seen_ids.add(pid)
            rec["is_demo"] = bool(rec.get("is_demo", False))
            merged.append(rec)
    for rec in local_records:
        pid = rec.get("id")
        if pid and pid not in seen_ids:
            seen_ids.add(pid)
            merged.append(rec)

    if not merged:
        demo_preset = {
            "id": "demo-fintech",
            "user_id": None,
            "project_name": "Fintech Payment Gateway (Demo)",
            "mode": "HYBRID",
            "url": "https://demo-fintech.auraglass.io",
            "repo": "https://github.com/auraglass/fintech-dashboard-api",
            "branch": "main",
            "is_demo": True,
            "created_at": "2026-10-24T02:15:22Z",
            "updated_at": "2026-10-24T02:15:22Z",
        }
        merged.append(demo_preset)

    return merged

async def delete_preset(preset_id: str, user_id: Optional[str] = None) -> bool:
    if is_supabase_enabled():
        try:
            headers = {**_supabase_headers(), "Prefer": "return=representation"}
            query_params = f"id=eq.{preset_id}"
            if user_id:
                query_params += f"&or=(user_id.eq.{user_id},user_id.is.null)"
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.delete(_supabase_url(f"presets?{query_params}"), headers=headers)
                if res.status_code == 200:
                    deleted = res.json()
                    return len(deleted) > 0
        except Exception as e:
            logger.error(f"[Supabase] Error saat delete_preset: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        if user_id:
            cursor = await db.execute("DELETE FROM presets WHERE id = ? AND (user_id = ? OR user_id IS NULL)", (preset_id, user_id))
        else:
            cursor = await db.execute("DELETE FROM presets WHERE id = ?", (preset_id,))
        await db.commit()
        return cursor.rowcount > 0

async def restore_demo_presets(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    if is_supabase_enabled():
        try:
            query_params = "is_demo=eq.false"
            if user_id:
                query_params += f"&user_id=eq.{user_id}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.delete(_supabase_url(f"presets?{query_params}"), headers=_supabase_headers())
        except Exception as e:
            logger.error(f"[Supabase] Error restore_demo_presets: {e}")

    await init_db()
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        if user_id:
            await db.execute("DELETE FROM presets WHERE is_demo = 0 AND user_id = ?", (user_id,))
        else:
            await db.execute("DELETE FROM presets WHERE is_demo = 0")
        await db.commit()

    return await list_presets(user_id)
