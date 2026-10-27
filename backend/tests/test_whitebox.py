import os
import tempfile
import unittest
import asyncio
from backend.services.whitebox_scanner import (
    normalize_github_target,
    parse_repo_dependencies,
    scan_sast_and_secrets,
    detect_tech_stack_from_dir,
    scan_whitebox
)

class TestWhiteboxScanner(unittest.TestCase):
    def test_normalize_github_target(self):
        urls = [
            ("https://github.com/AdliXSec/dikelolain-software-testing", ("https://github.com/AdliXSec/dikelolain-software-testing.git", "AdliXSec", "dikelolain-software-testing")),
            ("https://github.com/AdliXSec/dikelolain-software-testing.git", ("https://github.com/AdliXSec/dikelolain-software-testing.git", "AdliXSec", "dikelolain-software-testing")),
            ("AdliXSec/dikelolain-software-testing/", ("https://github.com/AdliXSec/dikelolain-software-testing.git", "AdliXSec", "dikelolain-software-testing")),
        ]
        for url, expected in urls:
            res = normalize_github_target(url)
            self.assertEqual(res, expected)

    def test_nested_composer_dependencies_and_blade_sast(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_app = os.path.join(tmpdir, "dikelolain-app")
            views_dir = os.path.join(nested_app, "resources", "views")
            os.makedirs(views_dir, exist_ok=True)

            # 1. Mock composer.lock in nested folder
            composer_lock_content = '''{
                "packages": [
                    {"name": "guzzlehttp/guzzle", "version": "7.11.1"},
                    {"name": "laravel/framework", "version": "12.62.0"}
                ],
                "packages-dev": []
            }'''
            with open(os.path.join(nested_app, "composer.lock"), "w") as f:
                f.write(composer_lock_content)

            # 2. Mock artisan & package.json for tech stack detection
            with open(os.path.join(nested_app, "artisan"), "w") as f:
                f.write("#!/usr/bin/env php\n")
            with open(os.path.join(nested_app, "package.json"), "w") as f:
                f.write('{"devDependencies": {"tailwindcss": "^3.0.0"}}')

            # 3. Mock Blade template with unescaped variable
            blade_file = os.path.join(views_dir, "test.blade.php")
            with open(blade_file, "w") as f:
                f.write('<h1>{!! $userInputTitle !!}</h1>\n')

            # Test Tech Stack
            stack = detect_tech_stack_from_dir(tmpdir)
            self.assertIn("Laravel", stack)
            self.assertIn("Blade", stack)
            self.assertIn("Tailwind CSS", stack)

            # Test Dependency Parser (SCA)
            packages, _ = parse_repo_dependencies(tmpdir)
            pkg_names = [p["name"] for p in packages]
            self.assertIn("guzzlehttp/guzzle", pkg_names)
            self.assertIn("laravel/framework", pkg_names)

            # Test SAST Blade XSS
            findings = scan_sast_and_secrets(tmpdir)
            blade_findings = [f for f in findings if f.get("rule_id") == "SAST-BLADE-UNESCAPED-XSS"]
            self.assertGreaterEqual(len(blade_findings), 1)
            self.assertEqual(blade_findings[0]["cwe_id"], "CWE-79")

    def test_demo_mode_scan_whitebox(self):
        async def run_test():
            stages_emitted = []
            async def mock_callback(stage, progress, msg):
                stages_emitted.append((stage, progress))

            findings, stack, ai_status = await scan_whitebox("demo-mode-repo", progress_callback=mock_callback)
            self.assertGreater(len(findings), 0)
            self.assertIn("React", stack)
            stage_keys = [s[0] for s in stages_emitted]
            self.assertIn("WB_INIT", stage_keys)
            self.assertIn("WB_SCA_CVE", stage_keys)
            self.assertIn("WB_AST_XSS", stage_keys)
            self.assertIn("WB_SECRETS", stage_keys)
            self.assertIn("WB_TAINT_LOGIC", stage_keys)

        asyncio.run(run_test())

    def test_sparse_exclude_patterns_configured(self):
        from backend.services.whitebox_scanner import SPARSE_EXCLUDE_PATTERNS, IGNORED_DIRS
        self.assertIn("!*.mp4", SPARSE_EXCLUDE_PATTERNS)
        self.assertIn("!*.zip", SPARSE_EXCLUDE_PATTERNS)
        self.assertIn(".parcel-cache", IGNORED_DIRS)

    def test_detect_code_language_multi_stack(self):
        from backend.services.whitebox_scanner import detect_code_language
        self.assertEqual(detect_code_language("app/main.py"), "python")
        self.assertEqual(detect_code_language("routes/api.php"), "php")
        self.assertEqual(detect_code_language("views/welcome.blade.php"), "php")
        self.assertEqual(detect_code_language("src/App.tsx"), "typescript")
        self.assertEqual(detect_code_language("server/index.js"), "javascript")
        self.assertEqual(detect_code_language("cmd/main.go"), "go")
        self.assertEqual(detect_code_language("src/main.rs"), "rust")
        self.assertEqual(detect_code_language("src/Application.java"), "java")
        self.assertEqual(detect_code_language("Program.cs"), "csharp")
        self.assertEqual(detect_code_language("contracts/Token.sol"), "solidity")
        self.assertEqual(detect_code_language("Dockerfile"), "dockerfile")
        self.assertEqual(detect_code_language("deploy/docker-compose.yml"), "yaml")
        # Snippet content sniffing fallback
        self.assertEqual(detect_code_language("unknown.txt", snippet="def audit_logic():\n    return True"), "python")
        self.assertEqual(detect_code_language("snippet", snippet="<?php echo 'test'; ?>"), "php")
        self.assertEqual(detect_code_language("snippet", snippet="const handler = async (req: Request) => {}"), "typescript")

    def test_multi_stack_heuristics(self):
        from backend.services.whitebox_scanner import scan_system_logic_heuristics
        with tempfile.TemporaryDirectory() as tmpdir:
            py_code = 'import os\n\ndef run_cmd(u):\n    os.system(f"echo {u}")\n'
            js_code = 'const { exec } = require("child_process");\nexec("rm -rf " + folder);\n'
            docker_code = 'FROM alpine:latest\nRUN apk add curl\nCMD ["sh"]\n'

            logic_files = [
                ("backend/cmd.py", py_code),
                ("server/runner.js", js_code),
                ("Dockerfile", docker_code)
            ]
            findings = scan_system_logic_heuristics(tmpdir, logic_files)
            rule_ids = [f.get("rule_id") for f in findings]
            self.assertIn("SAST-PY-COMMAND-INJECTION", rule_ids)
            self.assertIn("SAST-JS-COMMAND-INJECTION", rule_ids)
            self.assertIn("SAST-DOCKER-ROOT-USER", rule_ids)

            # Ensure all findings carry compliant remediation with English takeaway
            for f in findings:
                remed = f.get("ai_remediation")
                self.assertIsNotNone(remed)
                self.assertTrue(len(remed.get("remediation_steps", [])) > 0)
                # Remediations must have structured code_patch
                self.assertIn("code_patch", remed)

if __name__ == "__main__":
    unittest.main()
