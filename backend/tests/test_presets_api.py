import unittest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database import init_db

class TestPresetsEndpoints(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()

    async def test_presets_api_flow(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /api/presets (default returns demo preset)
            get_res = await client.get("/api/presets")
            self.assertEqual(get_res.status_code, 200, get_res.text)
            presets = get_res.json()
            self.assertTrue(len(presets) >= 1)
            self.assertEqual(presets[0]["id"], "demo-fintech")

            # 2. POST /api/presets (create custom preset)
            create_res = await client.post(
                "/api/presets",
                json={
                    "project_name": "API Payment Staging",
                    "mode": "BLACKBOX",
                    "url": "https://api-staging.example.com",
                    "repo": "",
                    "branch": "main",
                    "is_demo": False,
                },
            )
            self.assertEqual(create_res.status_code, 201, create_res.text)
            created_preset = create_res.json()
            self.assertEqual(created_preset["project_name"], "API Payment Staging")
            self.assertEqual(created_preset["mode"], "BLACKBOX")
            new_id = created_preset["id"]

            # 3. GET /api/presets again to verify new preset is listed
            get_res2 = await client.get("/api/presets")
            self.assertEqual(get_res2.status_code, 200)
            ids = [p["id"] for p in get_res2.json()]
            self.assertIn(new_id, ids)

            # 4. DELETE /api/presets/{id}
            del_res = await client.delete(f"/api/presets/{new_id}")
            self.assertEqual(del_res.status_code, 200)
            self.assertTrue(del_res.json().get("success"))

            # 5. GET /api/presets again to verify it was removed
            get_res3 = await client.get("/api/presets")
            ids3 = [p["id"] for p in get_res3.json()]
            self.assertNotIn(new_id, ids3)

if __name__ == "__main__":
    unittest.main()
