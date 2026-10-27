"""
Katalog Sensitive Paths & File Probing.
Daftar path dan file sensitif yang dipindai untuk mendeteksi kebocoran kredensial,
file cadangan (backup), repositori versi (Git), dan endpoint konfigurasi internal.
Format tuple: (path: str, category: str, severity: str, description: str)
"""

from typing import List, Tuple

DEFAULT_SENSITIVE_PATHS: List[Tuple[str, str, str, str]] = [
    # --- Konfigurasi Lingkungan & Rahasia (Environment Secrets) ---
    ("/.env", "Config & Rahasia", "CRITICAL", "File konfigurasi environment (.env) berisi kredensial database dan API key publik."),
    ("/.env.local", "Config & Rahasia", "CRITICAL", "File konfigurasi local environment (.env.local) terekspos tanpa proteksi."),
    ("/.env.production", "Config & Rahasia", "CRITICAL", "File konfigurasi environment produksi terekspos."),
    ("/.env.backup", "Config & Rahasia", "CRITICAL", "File backup konfigurasi (.env.backup) terekspos tanpa proteksi autentikasi."),
    ("/config.json", "Config & Rahasia", "HIGH", "File konfigurasi aplikasi frontend/backend terekspos publik."),
    ("/appsettings.json", "Config & Rahasia", "HIGH", "File konfigurasi .NET / Core appsettings.json terekspos."),

    # --- Debug & Information Leak ---
    ("/phpinfo.php", "Debug & Information Leak", "HIGH", "Halaman diagnostik phpinfo() mengekspos variabel environment dan modul server."),
    ("/info.php", "Debug & Information Leak", "HIGH", "Halaman diagnostik PHP mengekspos konfigurasi server internal."),
    ("/server-status", "Apache Server Status", "HIGH", "Halaman pemantauan Apache server-status terbuka publik."),

    # --- Source Code & Version Control ---
    ("/.git/HEAD", "Source Code Repo", "CRITICAL", "Direktori repositori Git terekspos; penyerang dapat mengunduh seluruh source code proyek."),
    ("/.git/config", "Source Code Repo", "CRITICAL", "File konfigurasi Git terekspos, mengungkap URL upstream dan branch internal."),
    ("/.vscode/settings.json", "Editor Config", "MEDIUM", "Konfigurasi workspace VS Code terekspos."),
    ("/.idea/workspace.xml", "Editor Config", "MEDIUM", "Konfigurasi workspace JetBrains IDE terekspos."),

    # --- Database & Arsip Backup ---
    ("/backup.zip", "Database / Backup File", "CRITICAL", "Arsip file cadangan sistem (backup.zip) dapat diunduh tanpa autentikasi."),
    ("/backup.tar.gz", "Database / Backup File", "CRITICAL", "Cadangan sistem tar.gz terekspos publik."),
    ("/dump.sql", "Database / Backup File", "CRITICAL", "Database SQL dump terekspos langsung ke internet."),
    ("/database.sql", "Database / Backup File", "CRITICAL", "Berkas SQL database terekspos."),
    ("/db.sqlite3", "Database / Backup File", "CRITICAL", "Database SQLite lokal terekspos dan dapat diunduh langsung."),

    # --- CMS & Framework Specifics ---
    ("/wp-config.php.bak", "WordPress Config Backup", "CRITICAL", "Cadangan file wp-config berisi password database MySQL."),
    ("/wp-config.php~", "WordPress Config Backup", "CRITICAL", "File editor swap/backup konfigurasi WordPress terbuka."),
    ("/_next/static/", "Framework Static", "INFO", "Direktori aset statis Next.js."),

    # --- API Documentation & Introspection ---
    ("/swagger.json", "API Documentation", "MEDIUM", "Spesifikasi endpoint internal Swagger/OpenAPI terbuka untuk publik."),
    ("/api-docs", "API Documentation", "INFO", "Dokumentasi antarmuka API publik."),
    ("/openapi.json", "API Documentation", "INFO", "Skema OpenAPI v3 terbuka untuk publik."),
    ("/graphql", "API Documentation", "INFO", "Endpoint GraphQL aktif (cek introspeksi query)."),

    # --- Microservices & Cloud Actuators ---
    ("/actuator/health", "Spring Actuator", "LOW", "Spring Boot Actuator health check endpoint terbuka."),
    ("/actuator/env", "Spring Actuator", "CRITICAL", "Spring Boot Actuator env endpoint mengekspos konfigurasi memori dan rahasia."),
    ("/actuator/heapdump", "Spring Actuator", "CRITICAL", "Spring Boot heapdump mengekspos memori JVM penuh beserta token/kredensial."),

    # --- Web Standards & Discovery ---
    ("/robots.txt", "Standar Recon", "INFO", "File robots.txt memetakan direktori rahasia atau terlarang (Disallow)."),
    ("/sitemap.xml", "Standar Recon", "INFO", "Peta situs XML untuk indexing mesin pencari."),
    ("/.well-known/security.txt", "Standar Recon", "INFO", "Informasi kontak dan kebijakan keamanan sistem."),
    ("/.htaccess", "Web Server Config", "HIGH", "File konfigurasi Apache (.htaccess) dapat diakses publik."),
]

CURATED_SENSITIVE_PATHS: List[Tuple[str, str, str, str]] = DEFAULT_SENSITIVE_PATHS
