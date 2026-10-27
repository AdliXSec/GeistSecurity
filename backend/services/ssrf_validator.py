import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional
from backend.config import settings

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Cloud Metadata IP ranges yang mutlak dilarang (bahkan saat lab testing diizinkan)
# untuk mencegah pencurian credential instance cloud (IMDS)
METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
]

DEMO_DOMAINS = [
    "auraglass.io",
    "startupkamu.id",
    "umkm-nusantara.id",
    "example.com",
    "demo-toko.startupkamu.id",
    "demo-fintech.auraglass.io"
]

def validate_target_url(target_url: str, allow_local_lab: Optional[bool] = None) -> Tuple[bool, Optional[str]]:
    """
    Validasi URL target terhadap serangan SSRF (Server-Side Request Forgery).
    Mengembalikan (is_valid, error_message).

    Dalam Demo Mode atau jika allow_local_lab diaktifkan:
    - Pengguna bebas memasukkan link kustom untuk pengujian (termasuk lab pribadi
      di http://0.0.0.0:1412/, localhost, 127.0.0.1, atau port kustom lainnya).
    - IP metadata cloud (169.254.169.254) tetap diproteksi.
    """
    if not target_url:
        return True, None

    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False, f"Protokol tidak didukung: '{parsed.scheme}'. Hanya http dan https yang diizinkan."

        hostname = parsed.hostname
        if not hostname:
            return False, "Format URL tidak valid: hostname tidak ditemukan."

        # Tentukan status mode lab/demo
        lab_allowed = (
            allow_local_lab
            if allow_local_lab is not None
            else bool(getattr(settings, "ALLOW_LOCAL_LAB", False) or getattr(settings, "DEMO_MODE", False))
        )

        # 1. Cek bypass domain demo terdaftar
        for d in DEMO_DOMAINS:
            if hostname == d or hostname.endswith("." + d):
                return True, None

        # 2. Cek host loopback/lab lokal eksplisit jika lab_allowed aktif
        is_local_host = (
            hostname in ("0.0.0.0", "127.0.0.1", "localhost")
            or hostname.startswith("127.")
            or hostname.endswith(".local")
        )

        if lab_allowed and is_local_host:
            return True, None

        # 3. Resolusi IP address
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ip_str = addr_info[0][4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Cloud Metadata IP selalu dilarang dalam mode apa pun
            for meta_net in METADATA_NETWORKS:
                if ip_obj in meta_net:
                    return False, f"Anti-SSRF Protection: Host '{hostname}' mengarah ke Cloud Metadata IP ({ip_str}) yang dilarang."

            # Jika lab_allowed aktif, izinkan IP privat/loopback untuk lab pengujian
            if lab_allowed:
                return True, None

            # Mode produksi ketat: blokir semua jaringan privat dan loopback
            for net in PRIVATE_NETWORKS:
                if ip_obj in net:
                    return False, f"Anti-SSRF Protection: Host '{hostname}' mengarah ke IP privat ({ip_str}) yang diblokir."

        except socket.gaierror:
            if lab_allowed:
                # Mode lab/demo: izinkan target jika hostname tidak dapat di-resolve ke internet
                return True, None
            return False, f"Gagal menyelesaikan hostname '{hostname}' melalui DNS."

        return True, None

    except Exception as e:
        return False, f"Terjadi kesalahan saat memvalidasi URL: {str(e)}"
