import unittest
from datetime import datetime, timezone
from backend.database import (
    init_db, save_audit, get_audit, delete_audit, delete_audits_batch, list_audits,
    save_preset, list_presets, delete_preset, restore_demo_presets,
)

class TestDatabaseOperations(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()

    async def test_audit_lifecycle_crud(self):
        test_session_id = "test-session-crud-12345"
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Save
        await save_audit(
            session_id=test_session_id,
            project_name="Test CRUD Project",
            mode="BLACKBOX",
            status="COMPLETED",
            target_url="https://example.com",
            github_repo_url=None,
            branch="feat/auth",
            created_at=now_str,
            updated_at=now_str,
            score=85,
            grade="B",
            grade_label="Grade B (85/100)",
            critical_count=0,
            high_count=1,
            duration_ms=15000,
            report_json={"findings": []}
        )

        # 2. Get
        retrieved = await get_audit(test_session_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.get("project_name"), "Test CRUD Project")

        # 3. List contains item with branch
        audits = await list_audits()
        matched = [a for a in audits if a.get("session_id") == test_session_id]
        self.assertTrue(len(matched) > 0)
        self.assertEqual(matched[0].get("branch"), "feat/auth")

        # 4. Delete
        deleted = await delete_audit(test_session_id)
        self.assertTrue(deleted)

        # 5. Verify deleted
        after_delete = await get_audit(test_session_id)
        self.assertIsNone(after_delete)

        # 6. Delete again returns False
        deleted_again = await delete_audit(test_session_id)
        self.assertFalse(deleted_again)

    async def test_batch_delete_audits(self):
        sids = ["test-batch-1", "test-batch-2", "test-batch-3"]
        now_str = datetime.now(timezone.utc).isoformat()
        for sid in sids:
            await save_audit(
                session_id=sid,
                project_name=f"Project {sid}",
                mode="WHITEBOX",
                status="COMPLETED",
                target_url=None,
                github_repo_url="https://github.com/example/repo",
                branch="main",
                created_at=now_str,
                updated_at=now_str,
                score=90,
                grade="A",
                grade_label="Grade A (90/100)",
                critical_count=0,
                high_count=0,
                duration_ms=5000,
                report_json={"findings": []}
            )

        # Batch delete
        deleted_count = await delete_audits_batch(sids)
        self.assertEqual(deleted_count, 3)

        # Verify all are deleted
        for sid in sids:
            self.assertIsNone(await get_audit(sid))

    async def test_supabase_helper_functions(self):
        from backend.database import is_supabase_enabled, _supabase_headers, _supabase_url
        from backend.config import settings

        # By default in test environment, Supabase URL is empty
        prev_url = settings.SUPABASE_URL
        prev_key = settings.SUPABASE_KEY
        try:
            settings.SUPABASE_URL = ""
            settings.SUPABASE_KEY = ""
            self.assertFalse(is_supabase_enabled())

            settings.SUPABASE_URL = "https://exampleproj.supabase.co"
            settings.SUPABASE_KEY = "test-service-key"
            self.assertTrue(is_supabase_enabled(ignore_test=True))
            self.assertEqual(_supabase_url("audits"), "https://exampleproj.supabase.co/rest/v1/audits")
            headers = _supabase_headers()
            self.assertEqual(headers["apikey"], "test-service-key")
            self.assertEqual(headers["Authorization"], "Bearer test-service-key")
        finally:
            settings.SUPABASE_URL = prev_url
            settings.SUPABASE_KEY = prev_key

    async def test_preset_lifecycle_crud(self):
        now_str = datetime.now(timezone.utc).isoformat()
        preset_id = "test-custom-preset-1"

        # 1. Save preset
        saved = await save_preset(
            preset_id=preset_id,
            project_name="Test Staging API",
            mode="WHITEBOX",
            url="https://staging.internal",
            repo="https://github.com/myorg/api",
            branch="develop",
            created_at=now_str,
            updated_at=now_str,
            user_id="user-xyz-123",
            is_demo=False,
        )
        self.assertEqual(saved["id"], preset_id)
        self.assertEqual(saved["project_name"], "Test Staging API")

        # 2. List presets for user
        presets = await list_presets(user_id="user-xyz-123")
        ids = [p["id"] for p in presets]
        self.assertIn(preset_id, ids)

        # 3. Delete preset
        deleted = await delete_preset(preset_id=preset_id, user_id="user-xyz-123")
        self.assertTrue(deleted)

        # 4. Verify deleted
        presets_after = await list_presets(user_id="user-xyz-123")
        ids_after = [p["id"] for p in presets_after]
        self.assertNotIn(preset_id, ids_after)

if __name__ == "__main__":
    unittest.main()
