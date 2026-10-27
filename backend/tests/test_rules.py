import unittest
from backend.rules import (
    get_curated_ports,
    get_known_cves,
    get_sensitive_paths,
    get_security_headers,
    COMMON_PORTS,
    KNOWN_CVES,
    CURATED_SENSITIVE_PATHS,
    SECURITY_HEADERS,
)

class TestModularRules(unittest.TestCase):
    def test_ports_catalog(self):
        ports = get_curated_ports()
        port_numbers = [p[0] for p in ports]
        # Pastikan port standar dan database krusial terdaftar
        self.assertIn(80, port_numbers)
        self.assertIn(443, port_numbers)
        self.assertIn(3306, port_numbers)
        self.assertIn(5432, port_numbers)
        self.assertIn(6379, port_numbers)
        self.assertIn(27017, port_numbers)
        self.assertGreaterEqual(len(ports), 12)

    def test_cves_catalog(self):
        cves = get_known_cves()
        components = [c["component"] for c in cves]
        # Pastikan CVE komponen web umum terdaftar
        self.assertIn("nginx", components)
        self.assertIn("apache", components)
        self.assertIn("jquery", components)
        self.assertIn("php", components)
        
        # Validasi struktur tiap entry CVE
        for c in cves:
            self.assertIn("cve", c)
            self.assertIn("pattern", c)
            self.assertIn("severity", c)
            self.assertIn("cvss", c)

    def test_sensitive_paths_catalog(self):
        paths = get_sensitive_paths()
        path_names = [p[0] for p in paths]
        # Pastikan file rahasia & backup krusial ada di katalog
        self.assertIn("/.env", path_names)
        self.assertIn("/.git/HEAD", path_names)
        self.assertIn("/dump.sql", path_names)
        self.assertIn("/actuator/env", path_names)
        self.assertIn("/wp-config.php.bak", path_names)
        self.assertGreaterEqual(len(paths), 20)

    def test_security_headers_catalog(self):
        headers = get_security_headers()
        self.assertIn("strict-transport-security", headers)
        self.assertIn("content-security-policy", headers)
        self.assertIn("x-content-type-options", headers)
        self.assertIn("x-frame-options", headers)

if __name__ == "__main__":
    unittest.main()
