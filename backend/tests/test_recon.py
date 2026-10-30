import unittest
import asyncio
from backend.services.ssrf_validator import validate_target_url
from backend.services.entropy import calculate_shannon_entropy
from backend.services.redactor import redact_secret
from backend.services.scoring import calculate_posture_score
from backend.services.recon_engine import run_comprehensive_recon, is_valid_leak_content

class TestSecurityEngines(unittest.TestCase):
    def test_is_valid_leak_content(self):
        # 1. .env file tests
        self.assertTrue(is_valid_leak_content("/.env", "DB_PASSWORD=secret123\nAPP_KEY=base64:xyz"))
        self.assertFalse(is_valid_leak_content("/.env", "<html><body>Custom 404 Not Found</body></html>"))
        self.assertFalse(is_valid_leak_content("/.env", ""))

        # 2. .git tests
        self.assertTrue(is_valid_leak_content("/.git/HEAD", "ref: refs/heads/main\n"))
        self.assertFalse(is_valid_leak_content("/.git/HEAD", "<!DOCTYPE html><html>404</html>"))

        # 3. .htaccess tests
        self.assertTrue(is_valid_leak_content("/.htaccess", "RewriteEngine On\nRewriteRule ^.*$ index.php [L]"))
        self.assertFalse(is_valid_leak_content("/.htaccess", "<html>Error</html>"))
    def test_ssrf_validator(self):
        # Strict mode: Localhost & Loopback blocked
        self.assertFalse(validate_target_url("http://localhost", allow_local_lab=False)[0])
        self.assertFalse(validate_target_url("http://127.0.0.1:8080", allow_local_lab=False)[0])
        self.assertFalse(validate_target_url("http://127.0.0.5", allow_local_lab=False)[0])

        # Strict mode: Private RFC 1918 subnets blocked
        self.assertFalse(validate_target_url("http://10.0.0.1", allow_local_lab=False)[0])
        self.assertFalse(validate_target_url("http://192.168.1.1", allow_local_lab=False)[0])
        self.assertFalse(validate_target_url("http://172.16.0.1", allow_local_lab=False)[0])

        # Cloud Metadata IP (always blocked in both strict and lab modes)
        self.assertFalse(validate_target_url("http://169.254.169.254", allow_local_lab=False)[0])
        self.assertFalse(validate_target_url("http://169.254.169.254", allow_local_lab=True)[0])

        # Valid public target
        self.assertTrue(validate_target_url("https://example.com", allow_local_lab=False)[0])

        # Lab / Demo mode: allows private lab & loopback targets (0.0.0.0:1412, localhost)
        self.assertTrue(validate_target_url("http://0.0.0.0:1412/", allow_local_lab=True)[0])
        self.assertTrue(validate_target_url("http://127.0.0.1:1412/", allow_local_lab=True)[0])
        self.assertTrue(validate_target_url("http://localhost:1412/", allow_local_lab=True)[0])

    def test_entropy_and_redaction(self):
        high_entropy = "sk-proj-9b4e182390fba81c0024ffae4109b"
        entropy = calculate_shannon_entropy(high_entropy)
        self.assertGreaterEqual(entropy, 4.0)

        redacted = redact_secret(high_entropy)
        self.assertIn("****", redacted)
        self.assertNotIn("182390fba81c", redacted)

    def test_scoring_formula(self):
        # 1 Critical (-25) -> max grade locked at D
        res1 = calculate_posture_score([{"severity": "CRITICAL"}])
        self.assertEqual(res1["score"], 75)
        self.assertEqual(res1["grade"], "D")

        # 0 Critical, 1 High (-15), 1 Medium (-7) -> 100 - 22 = 78 (C: 65-79)
        res2 = calculate_posture_score([{"severity": "HIGH"}, {"severity": "MEDIUM"}])
        self.assertEqual(res2["score"], 78)
        self.assertEqual(res2["grade"], "C")

    def test_comprehensive_recon_mock(self):
        async def _run():
            recon_res = await run_comprehensive_recon("https://demo-fintech.auraglass.io")
            self.assertIn("open_ports", recon_res)
            self.assertIn("ssl_summary", recon_res)
            self.assertIn("detected_tech", recon_res)
            self.assertIn("sensitive_dirs", recon_res)
            self.assertIn("html_leaks", recon_res)
            self.assertIn("js_assets", recon_res)
            self.assertIn("discovered_parameters", recon_res)
            self.assertIn("findings", recon_res)
            self.assertGreater(len(recon_res["findings"]), 0)
            self.assertGreater(len(recon_res["js_assets"]), 0)

        asyncio.run(_run())

    def test_parameter_scanning(self):
        from bs4 import BeautifulSoup
        from backend.services.recon_engine import scan_url_and_form_parameters

        sample_html = """
        <html>
            <a href="/login?redirect_to=https://evil.com&user_id=123">Login</a>
            <form action="/search" method="get">
                <input type="text" name="q" value="test" />
                <input type="hidden" name="token" value="secret_abc" />
            </form>
            <form action="/admin" method="post">
                <input type="text" name="role" value="admin" />
                <input type="checkbox" name="debug" checked />
            </form>
        </html>
        """
        target_url = "https://example.com/portal?debug=1&api_key=secretkey123"
        soup = BeautifulSoup(sample_html, "html.parser")

        async def _test():
            param_items, param_findings = await scan_url_and_form_parameters(
                target_url, {}, sample_html, soup, client=None
            )
            param_names = [p["name"] for p in param_items]
            self.assertIn("debug", param_names)
            self.assertIn("api_key", param_names)
            self.assertIn("redirect_to", param_names)
            self.assertIn("token", param_names)
            self.assertIn("role", param_names)

            rule_ids = [f["rule_id"] for f in param_findings]
            self.assertIn("PARAM-SENSITIVE-DATA-IN-GET", rule_ids)
            self.assertIn("PARAM-POTENTIAL-OPEN-REDIRECT", rule_ids)
            self.assertIn("PARAM-PRIVILEGE-OR-IDOR-CANDIDATE", rule_ids)
            self.assertIn("PARAM-DEBUG-MODE-EXPOSURE", rule_ids)

        asyncio.run(_test())

    def test_advanced_engine_options_recon(self):
        from bs4 import BeautifulSoup
        from backend.services.recon_engine import scan_js_assets_and_secrets, scan_sensitive_directories
        from backend.models.schemas import AuditCreateRequest, AuditMode

        # 1. Pydantic schema validation for Advanced Engine Options
        req = AuditCreateRequest(
            project_name="Test Enterprise",
            mode=AuditMode.BLACKBOX,
            target_url="https://example.com",
            entropy_threshold=5.5,
            scan_depth="Shallow",
            js_exposure=False
        )
        self.assertEqual(req.entropy_threshold, 5.5)
        self.assertEqual(req.scan_depth, "Shallow")
        self.assertFalse(req.js_exposure)

        async def _test_async():
            soup = BeautifulSoup('<html><script src="/static/app.js"></script></html>', "html.parser")
            import httpx
            async with httpx.AsyncClient() as client:
                # 2. Test js_exposure=False skips deobfuscation
                assets, findings, tech = await scan_js_assets_and_secrets(
                    "https://example.com",
                    soup,
                    client,
                    entropy_threshold=4.2,
                    scan_depth="Deep",
                    js_exposure=False
                )
                self.assertEqual(len(assets), 1)
                self.assertEqual(assets[0]["status"], "Deobfuscation Skipped")
                self.assertEqual(len(findings), 0)

        asyncio.run(_test_async())

    def test_check_waf_challenge(self):
        from backend.services.recon_engine import check_waf_challenge, scan_misconfigurations

        # Case 1: Vercel Challenge Header
        is_waf, name = check_waf_challenge(403, {"x-vercel-mitigated": "challenge", "server": "Vercel"}, "")
        self.assertTrue(is_waf)
        self.assertIn("Vercel", name)

        # Case 2: Cloudflare Challenge HTML
        is_waf, name = check_waf_challenge(403, {"server": "cloudflare"}, "<html><title>Just a moment...</title></html>")
        self.assertTrue(is_waf)
        self.assertIn("Cloudflare", name)

        # Case 3: Empty headers shouldn't generate fake missing headers
        empty_findings = scan_misconfigurations("https://example.com", {}, None, "")
        self.assertEqual(len(empty_findings), 0)

    def test_authenticated_scanning_support(self):
        from backend.models.schemas import AuditCreateRequest, AuditMode

        # 1. Test Schema parsing with bearer token & cookie string
        req = AuditCreateRequest(
            project_name="Authenticated Target Test",
            mode=AuditMode.BLACKBOX,
            target_url="https://api.internal.target.id",
            auth_token="jwt_secret_token_12345",
            auth_cookie_string="session_id=sess_abc; role=admin",
            auth_headers={"X-Custom-Tenant": "sec-team-01"},
            auth_cookies={"pref": "dark"}
        )
        self.assertEqual(req.auth_token, "jwt_secret_token_12345")
        self.assertEqual(req.auth_cookie_string, "session_id=sess_abc; role=admin")
        self.assertEqual(req.auth_headers["X-Custom-Tenant"], "sec-team-01")

        # 2. Test Router Normalization Logic
        auth_headers = {}
        if req.auth_headers:
            for k, v in req.auth_headers.items():
                auth_headers[str(k).strip()] = str(v).strip()

        if req.auth_token:
            tok = req.auth_token.strip()
            auth_val = tok if tok.lower().startswith("bearer ") else f"Bearer {tok}"
            auth_headers["Authorization"] = auth_val

        auth_cookies = {}
        if req.auth_cookies:
            for k, v in req.auth_cookies.items():
                auth_cookies[str(k).strip()] = str(v).strip()

        if req.auth_cookie_string:
            for part in req.auth_cookie_string.split(";"):
                if "=" in part:
                    ckey, cval = part.split("=", 1)
                    auth_cookies[ckey.strip()] = cval.strip()

        self.assertEqual(auth_headers["Authorization"], "Bearer jwt_secret_token_12345")
        self.assertEqual(auth_headers["X-Custom-Tenant"], "sec-team-01")
        self.assertEqual(auth_cookies["session_id"], "sess_abc")
        self.assertEqual(auth_cookies["role"], "admin")
        self.assertEqual(auth_cookies["pref"], "dark")

        # 3. Test Redaction in TargetInfo to prevent sensitive data leakage
        redacted_headers = {k: "[REDACTED]" for k in auth_headers}
        redacted_cookies = {k: "[REDACTED]" for k in auth_cookies}
        self.assertEqual(redacted_headers["Authorization"], "[REDACTED]")
        self.assertEqual(redacted_cookies["session_id"], "[REDACTED]")

        # 4. Verify run_comprehensive_recon accepts auth arguments cleanly
        import inspect
        from backend.services.recon_engine import run_comprehensive_recon
        from backend.services.nuclei_scanner import run_nuclei_scan
        sig_recon = inspect.signature(run_comprehensive_recon)
        self.assertIn("auth_headers", sig_recon.parameters)
        self.assertIn("auth_cookies", sig_recon.parameters)

        sig_nuclei = inspect.signature(run_nuclei_scan)
        self.assertIn("auth_headers", sig_nuclei.parameters)
        self.assertIn("auth_cookies", sig_nuclei.parameters)

if __name__ == "__main__":
    unittest.main()
