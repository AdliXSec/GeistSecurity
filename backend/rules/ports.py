"""
Katalog Port Reconnaissance & Network Probing.
Daftar port yang dipindai secara asinkron untuk mendeteksi layanan terbuka dan risiko eksposur.
Untuk menambahkan port baru, cukup tambahkan tuple ke list DEFAULT_PORTS di bawah ini
atau melalui file konfigurasi JSON.
Format tuple: (port: int, service_name: str, risk_level: str, description: str)
"""

from typing import List, Tuple

# Default Curated Ports (12 standard ports + critical services)
DEFAULT_PORTS: List[Tuple[int, str, str, str]] = [
    (80, "HTTP", "INFO", "Layanan web standar tanpa enkripsi"),
    (443, "HTTPS", "INFO", "Layanan web terenkripsi SSL/TLS"),
    (3000, "Node.js / Dev Web", "MEDIUM", "Port default aplikasi Node.js, Express, atau Next.js dev"),
    (8000, "Python / Dev API", "MEDIUM", "Port default FastAPI, Django, atau uvicorn dev"),
    (8080, "Alt HTTP / Dev Proxy", "MEDIUM", "Port alternatif HTTP atau Tomcat / Spring Boot"),
    (8443, "Alt HTTPS", "INFO", "Port alternatif HTTPS"),
    (3306, "MySQL Database", "CRITICAL", "Database MySQL terbuka langsung ke jaringan luar"),
    (5432, "PostgreSQL Database", "CRITICAL", "Database PostgreSQL terbuka langsung ke jaringan luar"),
    (6379, "Redis Cache / Data Store", "CRITICAL", "Redis in-memory store rentan tanpa autentikasi"),
    (27017, "MongoDB Database", "CRITICAL", "Database MongoDB terbuka langsung"),
    (21, "FTP (File Transfer)", "HIGH", "Layanan transfer berkas FTP tanpa enkripsi"),
    (22, "SSH (Secure Shell)", "LOW", "Layanan remote shell terenkripsi"),
    (9200, "Elasticsearch", "CRITICAL", "Cluster Elasticsearch REST API terekspos"),
    (11211, "Memcached", "HIGH", "Memcached cache daemon terekspos"),
    (2375, "Docker Daemon (Unencrypted)", "CRITICAL", "Docker daemon API tanpa enkripsi TLS (Remote Root Takeover)"),
]

# Legacy compatibility list of 3-tuples: (port, service, risk)
COMMON_PORTS: List[Tuple[int, str, str]] = [
    (p[0], p[1], p[2]) for p in DEFAULT_PORTS
]
