import unittest
from backend.services.nuclei_scanner import (
    CURATED_TEMPLATES_DIR,
    PROFILES_DIR,
    NUCLEI_BIN,
    map_nuclei_severity,
    determine_category,
    resolve_profile_file
)
from backend.services.blackbox_scanner import deduplicate_and_merge_findings
from backend.models.schemas import AuditCreateRequest, TargetInfo

class TestNucleiScanner(unittest.TestCase):
    def test_curated_templates_exist(self):
        self.assertTrue(CURATED_TEMPLATES_DIR.exists(), "Direktori backend/rules/nuclei harus ada")
        self.assertTrue(PROFILES_DIR.exists(), "Direktori profiles harus ada")
        
        quick_prof = PROFILES_DIR / "secaudit-quick.yml"
        full_prof = PROFILES_DIR / "secaudit-full.yml"
        self.assertTrue(quick_prof.exists(), "Profile secaudit-quick.yml harus ada")
        self.assertTrue(full_prof.exists(), "Profile secaudit-full.yml harus ada")

    def test_severity_mapping(self):
        self.assertEqual(map_nuclei_severity("critical"), "CRITICAL")
        self.assertEqual(map_nuclei_severity("high"), "HIGH")
        self.assertEqual(map_nuclei_severity("medium"), "MEDIUM")
        self.assertEqual(map_nuclei_severity("low"), "LOW")
        self.assertEqual(map_nuclei_severity("info"), "INFO")
        self.assertEqual(map_nuclei_severity("unknown"), "MEDIUM")

    def test_category_determination(self):
        cat1 = determine_category(["cve", "rce"], "cve-2024-4577")
        self.assertIn(cat1, ["KNOWN_VULNERABILITY", "REMOTE_CODE_EXECUTION"])

        cat2 = determine_category(["takeover"], "aws-bucket-takeover")
        self.assertEqual(cat2, "SUBDOMAIN_TAKEOVER")

        cat3 = determine_category(["cors"], "cors-misconfig")
        self.assertEqual(cat3, "CORS_MISCONFIGURATION")

        cat4 = determine_category(["env"], "generic-env")
        self.assertEqual(cat4, "CREDENTIAL_LEAK")

    def test_resolve_profile_file(self):
        p_quick = resolve_profile_file("quick")
        self.assertTrue(p_quick.exists(), "Resolved quick profile harus ada di disk")
        p_full = resolve_profile_file("full")
        self.assertTrue(p_full.exists(), "Resolved full profile harus ada di disk")

    def test_deduplicate_and_merge_findings(self):
        recon_findings = [
            {
                "id": "bb-dir-1",
                "rule_id": "DIR_SENSITIVE_LEAK",
                "category": "SENSITIVE_DATA_EXPOSURE",
                "severity": "HIGH",
                "title": "Exposed Environment Variables (.env)",
                "description": "File .env ditemukan terbuka",
                "location": {"source_origin": "CURATED_DIR_FINDER", "path": "https://example.com/.env"},
                "evidence_metadata": {"status_code": 200}
            },
            {
                "id": "bb-port-80",
                "rule_id": "OPEN_PORT",
                "category": "PORT_SCAN",
                "severity": "LOW",
                "title": "Open Port 80",
                "description": "HTTP Port 80 terbuka",
                "location": {"source_origin": "NETWORK_PORT_SCANNER", "path": "https://example.com:80"}
            }
        ]

        nuclei_findings = [
            {
                "id": "bb-nuclei-laravel-env-1",
                "rule_id": "nuclei-laravel-env",
                "category": "CREDENTIAL_LEAK",
                "severity": "CRITICAL",
                "title": "Laravel .env Exposure",
                "description": "Nuclei detected exposed laravel .env",
                "location": {"source_origin": "NUCLEI_ENGINE", "path": "https://example.com/.env"},
                "evidence_metadata": {
                    "template_id": "laravel-env",
                    "matcher_name": "app-key",
                    "curl_command": "curl -i https://example.com/.env"
                }
            },
            {
                "id": "bb-nuclei-cve-1",
                "rule_id": "nuclei-cve-2024-4577",
                "category": "KNOWN_VULNERABILITY",
                "severity": "CRITICAL",
                "title": "PHP CGI RCE (CVE-2024-4577)",
                "description": "CISA KEV Vulnerability detected",
                "location": {"source_origin": "NUCLEI_ENGINE", "path": "https://example.com/index.php"}
            }
        ]

        merged = deduplicate_and_merge_findings(recon_findings, nuclei_findings)
        # Port 80 (unik recon) + CVE (unik nuclei) + 1 merged .env = total 3 findings (bukan 4!)
        self.assertEqual(len(merged), 3)

        # Cek apakah temuan .env di-merge & diperkaya
        env_finding = next((f for f in merged if "example.com/.env" in str(f.get("location", {}).get("path"))), None)
        self.assertIsNotNone(env_finding)
        self.assertEqual(env_finding["severity"], "CRITICAL")
        self.assertEqual(env_finding["location"]["source_origin"], "RECON_AND_NUCLEI")
        self.assertEqual(env_finding["evidence_metadata"]["nuclei_template_id"], "laravel-env")
        self.assertEqual(env_finding["evidence_metadata"]["curl_command"], "curl -i https://example.com/.env")

    def test_schema_nuclei_options(self):
        req = AuditCreateRequest(
            project_name="Test Project",
            target_url="https://example.com",
            enable_nuclei=True,
            nuclei_profile="full"
        )
        self.assertTrue(req.enable_nuclei)
        self.assertEqual(req.nuclei_profile, "full")

        ti = TargetInfo(
            enable_nuclei=True,
            nuclei_profile="quick",
            nuclei_findings_count=5
        )
        self.assertTrue(ti.enable_nuclei)
        self.assertEqual(ti.nuclei_findings_count, 5)
