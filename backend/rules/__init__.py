"""
Modular Security Rules & Signatures System.
Menghubungkan dan mengelola database aturan port, CVE, sensitive paths, dan HTTP security headers.
Mendukung penambahan langsung via file Python modular maupun melalui file konfigurasi JSON eksternal
(backend/rules/custom_rules.json).
"""

import json
import os
from typing import List, Dict, Any, Tuple
from pathlib import Path

from backend.rules.ports import DEFAULT_PORTS, COMMON_PORTS as BASE_PORTS
from backend.rules.cves import DEFAULT_CVES, KNOWN_CVES as BASE_CVES
from backend.rules.sensitive_paths import DEFAULT_SENSITIVE_PATHS, CURATED_SENSITIVE_PATHS as BASE_PATHS
from backend.rules.headers import DEFAULT_SECURITY_HEADERS, SECURITY_HEADERS as BASE_HEADERS

# Lokasi file custom rules opsional
DEFAULT_CUSTOM_RULES_PATH = Path(__file__).parent / "custom_rules.json"

def load_custom_rules(custom_file_path: Path = DEFAULT_CUSTOM_RULES_PATH) -> Dict[str, Any]:
    """Membaca file custom_rules.json jika ada."""
    if custom_file_path.is_file():
        try:
            with open(custom_file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[RulesLoader] Warning: Gagal membaca custom rules dari {custom_file_path}: {e}")
    return {}

def get_curated_ports() -> List[Tuple[int, str, str]]:
    """
    Mengambil daftar port untuk network scan (3-tuple: port, service, risk).
    Menggabungkan default ports dengan port tambahan dari custom_rules.json jika tersedia.
    """
    ports = list(BASE_PORTS)
    custom = load_custom_rules()
    for item in custom.get("additional_ports", []):
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            p_tuple = (int(item[0]), str(item[1]), str(item[2]))
            if not any(p[0] == p_tuple[0] for p in ports):
                ports.append(p_tuple)
    return ports

def get_known_cves() -> List[Dict[str, Any]]:
    """
    Mengambil database tanda tangan CVE.
    Menggabungkan default CVEs dengan CVE tambahan dari custom_rules.json jika tersedia.
    """
    cves = list(BASE_CVES)
    custom = load_custom_rules()
    for cve in custom.get("additional_cves", []):
        if isinstance(cve, dict) and "component" in cve and "cve" in cve:
            if not any(c.get("cve") == cve.get("cve") for c in cves):
                cves.append(cve)
    return cves

def get_sensitive_paths() -> List[Tuple[str, str, str, str]]:
    """
    Mengambil daftar path sensitif (4-tuple: path, category, severity, description).
    Menggabungkan default paths dengan path tambahan dari custom_rules.json jika tersedia.
    """
    paths = list(BASE_PATHS)
    custom = load_custom_rules()
    for item in custom.get("additional_sensitive_paths", []):
        if isinstance(item, (list, tuple)) and len(item) >= 4:
            p_tuple = (str(item[0]), str(item[1]), str(item[2]), str(item[3]))
            if not any(p[0] == p_tuple[0] for p in paths):
                paths.append(p_tuple)
    return paths

def get_security_headers() -> Dict[str, Dict[str, Any]]:
    """
    Mengambil daftar header keamanan HTTP.
    """
    headers = dict(BASE_HEADERS)
    custom = load_custom_rules()
    for h_name, meta in custom.get("additional_security_headers", {}).items():
        if isinstance(meta, dict) and h_name not in headers:
            headers[h_name] = meta
    return headers

# Dynamic active rule sets
COMMON_PORTS = get_curated_ports()
KNOWN_CVES = get_known_cves()
CURATED_SENSITIVE_PATHS = get_sensitive_paths()
SECURITY_HEADERS = get_security_headers()

__all__ = [
    "COMMON_PORTS",
    "KNOWN_CVES",
    "CURATED_SENSITIVE_PATHS",
    "SECURITY_HEADERS",
    "get_curated_ports",
    "get_known_cves",
    "get_sensitive_paths",
    "get_security_headers",
    "load_custom_rules",
]
