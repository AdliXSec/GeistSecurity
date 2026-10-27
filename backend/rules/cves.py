"""
Katalog Tanda Tangan Komponen & CVE (Common Vulnerabilities and Exposures).
Digunakan oleh Modul 3 untuk mencocokkan banner server, header teknologi, dan metadata HTML.
Untuk menambahkan CVE baru, cukup tambahkan dictionary ke list KNOWN_CVES di bawah ini.
"""

from typing import List, Dict, Any

# Database Tanda Tangan Komponen & CVE Lokal
DEFAULT_CVES: List[Dict[str, Any]] = [
    {
        "component": "nginx",
        "pattern": r"nginx[/\s]?([0-9.]+)",
        "vulnerable_versions": ["1.18.0", "1.18", "1.17", "1.16", "1.14"],
        "cve": "CVE-2021-23017",
        "cvss": 7.7,
        "severity": "HIGH",
        "title": "Nginx Outdated Version Rentan 1-byte Memory Overwrite (CVE-2021-23017)",
        "detail": "Versi Nginx yang digunakan rentan terhadap eksploitasi buffer overflow pada modul resolver DNS."
    },
    {
        "component": "apache",
        "pattern": r"apache[/\s]?([0-9.]+)",
        "vulnerable_versions": ["2.4.49", "2.4.50"],
        "cve": "CVE-2021-41773",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "title": "Apache HTTP Server RCE & Path Traversal (CVE-2021-41773)",
        "detail": "Kelemahan validasi path traversal memungkinkan pembacaan berkas sembarang atau eksekusi kode jarak jauh."
    },
    {
        "component": "jquery",
        "pattern": r"jquery[/\s\-_]?([0-9.]+)",
        "vulnerable_versions": ["2.1.4", "1.12.4", "1.11.3", "2.2.4", "3.3.1"],
        "cve": "CVE-2015-9251",
        "cvss": 7.2,
        "severity": "HIGH",
        "title": "jQuery Usang Rentan Cross-Site Scripting & Prototype Pollution (CVE-2015-9251)",
        "detail": "Versi jQuery lama mengeksekusi script secara otomatis saat parsing AJAX response bertipe text/javascript."
    },
    {
        "component": "php",
        "pattern": r"php[/\s]?([0-9.]+)",
        "vulnerable_versions": ["7.4.3", "7.4", "7.3", "7.2", "7.1", "5.6"],
        "cve": "CVE-2021-21703",
        "cvss": 8.1,
        "severity": "HIGH",
        "title": "PHP End-of-Life (EOL) & Unpatched Buffer Overflow (CVE-2021-21703)",
        "detail": "PHP 7.4 telah mencapai status End of Life dan tidak lagi menerima patch keamanan resmi."
    },
    {
        "component": "openssl",
        "pattern": r"openssl[/\s]?([0-9.]+)",
        "vulnerable_versions": ["1.0.1", "1.0.1f", "1.1.1k"],
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "HIGH",
        "title": "OpenSSL Heartbleed / Information Disclosure (CVE-2014-0160)",
        "detail": "Kebocoran memori pada implementasi TLS heartbeat extension memungkinkan pencurian kunci privat."
    },
    {
        "component": "wordpress",
        "pattern": r"wordpress[/\s]?([0-9.]+)",
        "vulnerable_versions": ["5.8.0", "5.7.0", "5.6.0", "5.5.0"],
        "cve": "CVE-2022-21661",
        "cvss": 8.0,
        "severity": "HIGH",
        "title": "WordPress SQL Injection via WP_Query (CVE-2022-21661)",
        "detail": "Kelemahan sanitasi query pada kelas WP_Query memungkinkan injeksi SQL tanpa autentikasi."
    }
]

KNOWN_CVES: List[Dict[str, Any]] = DEFAULT_CVES
