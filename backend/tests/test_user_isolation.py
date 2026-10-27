import unittest
import uuid
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone
from backend.main import app
from backend.database import init_db, save_audit, get_audit

class TestUserAuditIsolation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()

    async def test_audit_data_isolated_per_user(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            suffix_a = uuid.uuid4().hex[:6]
            suffix_b = uuid.uuid4().hex[:6]

            # 1. Register User A (Alice)
            reg_a = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": f"alice_{suffix_a}",
                    "email": f"alice_{suffix_a}@auraglass.test",
                    "password": "PasswordAlice123!",
                    "full_name": "Alice Security",
                },
            )
            self.assertEqual(reg_a.status_code, 200)
            token_a = reg_a.json()["access_token"]
            user_a_id = reg_a.json()["user"]["id"]

            # 2. Register User B (Bob)
            reg_b = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": f"bob_{suffix_b}",
                    "email": f"bob_{suffix_b}@auraglass.test",
                    "password": "PasswordBob123!",
                    "full_name": "Bob Penetration",
                },
            )
            self.assertEqual(reg_b.status_code, 200)
            token_b = reg_b.json()["access_token"]
            user_b_id = reg_b.json()["user"]["id"]

            # 3. Create Audit Session as User A
            session_a = f"audit-alice-{uuid.uuid4().hex[:8]}"
            now_iso = datetime.now(timezone.utc).isoformat()
            await save_audit(
                session_id=session_a,
                project_name="Alice Secret Fintech",
                mode="WHITEBOX",
                status="COMPLETED",
                target_url=None,
                github_repo_url="https://github.com/alice/fintech",
                branch="main",
                created_at=now_iso,
                updated_at=now_iso,
                score=92,
                grade="A",
                grade_label="Grade A (92/100)",
                critical_count=0,
                high_count=0,
                duration_ms=4500,
                report_json={"findings": []},
                user_id=user_a_id,
            )

            # 4. User A lists audits -> session_a is present
            resp_list_a = await client.get(
                "/api/v1/audits",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(resp_list_a.status_code, 200)
            items_a = resp_list_a.json()
            ids_a = [item["session_id"] for item in items_a]
            self.assertIn(session_a, ids_a)

            # 5. User B lists audits -> session_a is NOT present
            resp_list_b = await client.get(
                "/api/v1/audits",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            self.assertEqual(resp_list_b.status_code, 200)
            items_b = resp_list_b.json()
            ids_b = [item["session_id"] for item in items_b]
            self.assertNotIn(session_a, ids_b)

            # 6. Unauthenticated listing -> returns empty list
            resp_list_anon = await client.get("/api/v1/audits")
            self.assertEqual(resp_list_anon.status_code, 200)
            self.assertEqual(resp_list_anon.json(), [])

            # 7. User A accesses own audit status -> 200 OK
            resp_status_a = await client.get(
                f"/api/v1/audits/{session_a}",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(resp_status_a.status_code, 200)
            self.assertEqual(resp_status_a.json()["session_id"], session_a)

            # 8. User B attempts to access User A's audit status -> 403 Forbidden
            resp_status_b = await client.get(
                f"/api/v1/audits/{session_a}",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            self.assertEqual(resp_status_b.status_code, 403)
            self.assertIn("Akses ditolak", resp_status_b.json()["detail"])

            # 9. User B attempts to delete User A's audit -> User A's audit remains intact
            resp_del_b = await client.delete(
                f"/api/v1/audits/{session_a}",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            self.assertEqual(resp_del_b.status_code, 200)
            # Verify it is still in the database
            audit_still_exists = await get_audit(session_a)
            self.assertIsNotNone(audit_still_exists)

            # 10. User A deletes own audit -> Successfully deleted
            resp_del_a = await client.delete(
                f"/api/v1/audits/{session_a}",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            self.assertEqual(resp_del_a.status_code, 200)
            audit_deleted = await get_audit(session_a)
            self.assertIsNone(audit_deleted)

if __name__ == "__main__":
    unittest.main()
