import unittest
import uuid
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database import init_db

class TestAuthEndpoints(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()

    async def test_auth_register_and_login_flow(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            unique_suffix = uuid.uuid4().hex[:8]
            username = f"sec_operator_{unique_suffix}"
            email = f"operator_{unique_suffix}@security.corp"
            password = "SecurePassword2026!"

            # 1. Register new user
            reg_resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": username,
                    "email": email,
                    "password": password,
                    "full_name": "Chief Security Officer",
                },
            )
            self.assertEqual(reg_resp.status_code, 200, reg_resp.text)
            reg_data = reg_resp.json()
            self.assertIn("access_token", reg_data)
            self.assertEqual(reg_data["user"]["username"], username)
            self.assertEqual(reg_data["user"]["email"], email)

            token = reg_data["access_token"]

            # 2. Duplicate registration should fail (400)
            dup_resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": username,
                    "email": f"different_{unique_suffix}@corp.io",
                    "password": password,
                },
            )
            self.assertEqual(dup_resp.status_code, 400)
            self.assertIn("already taken", dup_resp.json()["detail"])

            # 3. Login with username and password
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "username_or_email": username,
                    "password": password,
                },
            )
            self.assertEqual(login_resp.status_code, 200)
            login_data = login_resp.json()
            self.assertIn("access_token", login_data)
            self.assertEqual(login_data["user"]["username"], username)

            # 4. Login with email and password
            login_email_resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "username_or_email": email,
                    "password": password,
                },
            )
            self.assertEqual(login_email_resp.status_code, 200)
            self.assertEqual(login_email_resp.json()["user"]["email"], email)

            # 5. Login with invalid password (401)
            bad_pw_resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "username_or_email": username,
                    "password": "WrongPassword!",
                },
            )
            self.assertEqual(bad_pw_resp.status_code, 401)
            self.assertIn("Invalid", bad_pw_resp.json()["detail"])

            # 6. Verify profile via /me with valid Bearer token
            me_resp = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(me_resp.status_code, 200)
            me_data = me_resp.json()
            self.assertEqual(me_data["username"], username)
            self.assertEqual(me_data["full_name"], "Chief Security Officer")

            # 7. Access /me without token fails (401)
            no_auth_resp = await client.get("/api/v1/auth/me")
            self.assertEqual(no_auth_resp.status_code, 401)
