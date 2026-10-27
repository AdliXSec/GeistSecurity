"""
Katalog Aturan HTTP Security Headers & Miskonfigurasi.
Digunakan oleh Modul 7 untuk mengecek kelengkapan hardening header HTTP.
"""

from typing import Dict, Any

DEFAULT_SECURITY_HEADERS: Dict[str, Dict[str, Any]] = {
    "strict-transport-security": {
        "rule_id": "HTTP-MISSING-HSTS",
        "severity": "HIGH",
        "title": "Missing Passive HTTP Security Header: HSTS (Strict-Transport-Security)",
        "cwe_id": "CWE-319",
        "cvss_score": 7.5,
        "detail": "Koneksi web tidak memaksakan HTTPS secara ketat, rentan terhadap Man-in-the-Middle (MitM) SSL stripping."
    },
    "content-security-policy": {
        "rule_id": "HTTP-MISSING-CSP",
        "severity": "HIGH",
        "title": "Missing Content Security Policy (CSP) Directives",
        "cwe_id": "CWE-1021",
        "cvss_score": 7.2,
        "detail": "Aplikasi tidak membatasi sumber eksekusi script dan sumber daya eksternal, memudahkan eksploitasi XSS."
    },
    "x-content-type-options": {
        "rule_id": "HTTP-MISSING-XCTO",
        "severity": "LOW",
        "title": "Missing Passive HTTP Security Header: X-Content-Type-Options: nosniff",
        "cwe_id": "CWE-79",
        "cvss_score": 3.7,
        "detail": "Browser dapat mencoba menebak (MIME-sniffing) tipe konten yang dieksekusi."
    },
    "x-frame-options": {
        "rule_id": "HTTP-MISSING-XFO",
        "severity": "MEDIUM",
        "title": "Missing Passive HTTP Security Header: X-Frame-Options (Clickjacking Protection)",
        "cwe_id": "CWE-1021",
        "cvss_score": 5.4,
        "detail": "Halaman web dapat disematkan di dalam <iframe> oleh domain berbahaya."
    },
    "referrer-policy": {
        "rule_id": "HTTP-MISSING-REFERRER-POLICY",
        "severity": "LOW",
        "title": "Missing Passive HTTP Security Header: Referrer-Policy",
        "cwe_id": "CWE-200",
        "cvss_score": 3.1,
        "detail": "Informasi URL lengkap (termasuk query parameters sensitif) dapat bocor ke pihak ketiga saat navigasi keluar."
    },
    "permissions-policy": {
        "rule_id": "HTTP-MISSING-PERMISSIONS-POLICY",
        "severity": "LOW",
        "title": "Missing Passive HTTP Security Header: Permissions-Policy",
        "cwe_id": "CWE-1021",
        "cvss_score": 2.8,
        "detail": "Aplikasi tidak membatasi akses peramban terhadap fitur hardware sensitif seperti kamera, mikrofon, atau geolokasi."
    }
}

SECURITY_HEADERS: Dict[str, Dict[str, Any]] = DEFAULT_SECURITY_HEADERS
