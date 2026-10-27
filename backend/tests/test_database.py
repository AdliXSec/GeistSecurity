import unittest
from datetime import datetime, timezone
from backend.database import init_db, save_audit, get_audit, delete_audit, delete_audits_batch, list_audits

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

if __name__ == "__main__":
    unittest.main()
