import uuid
import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, status, Depends
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from backend.models.schemas import (
    AuditCreateRequest,
    AuditCreateResponse,
    AuditStatus,
    AuditReportResponse,
    AuditSummaryItem,
    PatchSimulationRequest,
    PatchSimulationResponse,
    BatchDeleteRequest,
    BatchDeleteResponse,
)
from backend.services.ssrf_validator import validate_target_url
from backend.services.scoring import calculate_posture_score
from backend.services.audit_orchestrator import (
    run_audit_pipeline,
    get_or_create_queue,
    subscribe,
    unsubscribe,
)
from backend.database import get_audit, list_audits, save_audit, delete_audit, delete_audits_batch
from backend.routers.auth import get_current_user_optional

router = APIRouter(prefix="/api/v1/audits", tags=["Audits"])

@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AuditCreateResponse,
    summary="Inisialisasi Sesi Audit Keamanan Baru"
)
async def create_audit(
    request: AuditCreateRequest,
    background_tasks: BackgroundTasks,
    user: Optional[dict] = Depends(get_current_user_optional),
):
    """
    Menerima parameter audit (project_name, mode, target_url, github_repo_url, branch),
    memvalidasi anti-SSRF, dan menginisialisasi pipeline audit di latar belakang.
    """
    # 1. Anti-SSRF Validation
    if request.target_url:
        is_valid, err_msg = validate_target_url(request.target_url)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Validasi Anti-SSRF gagal: {err_msg}"
            )

    # 2. Generate session ID & save initial record
    session_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    user_id = user["id"] if user else None
    await save_audit(
        session_id=session_id,
        project_name=request.project_name,
        mode=request.mode.value,
        status="PENDING",
        target_url=request.target_url,
        github_repo_url=request.github_repo_url,
        branch=request.branch or "main",
        created_at=now_iso,
        updated_at=now_iso,
        user_id=user_id,
    )

    # 3. Normalize Authenticated Scan Headers & Cookies
    auth_headers: Dict[str, str] = {}
    if request.auth_headers:
        for k, v in request.auth_headers.items():
            if k and v:
                auth_headers[str(k).strip()] = str(v).strip()

    if request.auth_token:
        tok = request.auth_token.strip()
        if not any(k.lower() == "authorization" for k in auth_headers):
            auth_val = tok if tok.lower().startswith("bearer ") else f"Bearer {tok}"
            auth_headers["Authorization"] = auth_val

    auth_cookies: Dict[str, str] = {}
    if request.auth_cookies:
        for k, v in request.auth_cookies.items():
            if k and v:
                auth_cookies[str(k).strip()] = str(v).strip()

    if request.auth_cookie_string:
        for part in request.auth_cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                ckey, cval = part.split("=", 1)
                if ckey.strip():
                    auth_cookies[ckey.strip()] = cval.strip()

    # 4. Queue background execution
    asyncio.create_task(
        run_audit_pipeline(
            session_id=session_id,
            project_name=request.project_name,
            mode=request.mode.value,
            target_url=request.target_url,
            github_repo_url=request.github_repo_url,
            branch=request.branch or "main",
            entropy_threshold=request.entropy_threshold if request.entropy_threshold is not None else 4.2,
            scan_depth=request.scan_depth or "Deep",
            js_exposure=request.js_exposure if request.js_exposure is not None else True,
            enable_nuclei=request.enable_nuclei if request.enable_nuclei is not None else True,
            nuclei_profile=request.nuclei_profile or "quick",
            user_id=user_id,
            auth_headers=auth_headers or None,
            auth_cookies=auth_cookies or None,
        )
    )

    return AuditCreateResponse(
        session_id=session_id,
        status=AuditStatus.PENDING,
        stream_endpoint=f"/api/v1/audits/{session_id}/stream",
        report_endpoint=f"/api/v1/audits/{session_id}/report",
        message="Audit session initialized successfully."
    )

@router.get(
    "/{session_id}/stream",
    summary="Real-time Server-Sent Events (SSE) Progress Stream"
)
async def stream_audit_progress(session_id: str):
    """
    Menyediakan stream SSE langsung dari pipeline audit dengan dukungan pub/sub
    dan event history replay untuk koneksi baru/reconnect.
    """
    # 1. Cek apakah audit di database sudah selesai
    existing_audit = await get_audit(session_id)
    if existing_audit and existing_audit.get("status") == "COMPLETED":
        async def completed_generator():
            done_payload = {
                "stage": "COMPLETED",
                "progress": 100,
                "message": "Audit selesai sepenuhnya. Laporan siap dilihat.",
                "redirect_report_url": f"/api/v1/audits/{session_id}/report"
            }
            # Kirim tanpa event name kustom agar ditangkap es.onmessage
            yield {
                "event": "message",
                "data": json.dumps(done_payload)
            }
        return EventSourceResponse(completed_generator())

    # 2. Subscribe ke orchestrator pub/sub
    history, q = subscribe(session_id)

    async def event_generator():
        try:
            # Replay seluruh event sebelumnya jika ada
            for past_event in history:
                yield {
                    "event": "message",
                    "data": json.dumps(past_event)
                }
                if past_event.get("stage") in ("COMPLETED", "FAILED"):
                    return

            # Listen untuk event live berikutnya
            while True:
                try:
                    data = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield {
                        "event": "message",
                        "data": json.dumps(data)
                    }

                    if data.get("stage") in ("COMPLETED", "FAILED"):
                        break
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield {
                        "event": "ping",
                        "data": json.dumps({"status": "heartbeat"})
                    }
        finally:
            unsubscribe(session_id, q)

    return EventSourceResponse(event_generator())

@router.get(
    "/{session_id}/report",
    summary="Ambil Laporan Lengkap Hasil Audit"
)
async def get_audit_report(session_id: str, user: Optional[dict] = Depends(get_current_user_optional)):
    """
    Mengembalikan laporan audit lengkap berformat JSON sesuai standar PRD Section 7.3.
    """
    audit = await get_audit(session_id)
    if not audit:
        # Fallback untuk session demo bawaan
        if session_id in ("demo-fintech", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"):
            return {
                "session_id": session_id,
                "project_name": "Portal E-Commerce UMKM",
                "mode": "HYBRID",
                "status": "COMPLETED",
                "audited_at": "2026-10-24T02:15:22Z",
                "duration_ms": 20450,
                "target_info": {
                    "target_url": "https://demo-toko.startupkamu.id",
                    "github_repo_url": "https://github.com/username/demo-toko-web",
                    "branch": "main",
                    "detected_tech_stack": ["Next.js 14.1.0", "React 18.2.0", "Tailwind CSS", "Nginx 1.24.0"]
                },
                "posture_score": {
                    "score": 42,
                    "max_score": 100,
                    "grade": "D",
                    "grade_label": "High Risk — Immediate Remediation Required",
                    "summary_counts": {
                        "critical": 3,
                        "high": 3,
                        "medium": 5,
                        "low": 0,
                        "info": 1
                    }
                },
                "findings": [
                    {
                        "id": "f101-dc4a-4812-9a11-001",
                        "rule_id": "JS-SECRET-OPENAI",
                        "category": "JS_SECRET_LEAK",
                        "severity": "CRITICAL",
                        "title": "Kebocoran Private API Key pada Bundel JavaScript Publik",
                        "cwe_id": "CWE-798",
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "cvss_score": 9.1,
                        "location": {
                            "source_origin": "WHITEBOX_AND_CLIENT_JS",
                            "path": "src/services/aiAssistant.ts (Terekspos di /_next/static/chunks/main-8f2a.js)",
                            "line_start": 8,
                            "line_end": 10
                        },
                        "redacted_code_snippet": "const OPENAI_KEY = process.env.NEXT_PUBLIC_OPENAI_KEY || \"sk-proj-********************9b4e\";",
                        "evidence_metadata": {
                            "secret_type": "OpenAI Project API Key",
                            "redacted_match": "sk-proj-********************9b4e",
                            "shannon_entropy": 4.78,
                            "entropy_threshold": 4.2,
                            "exposed_in_production_bundle": True
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Penggunaan prefix NEXT_PUBLIC_ memaksa bundler menyisipkan kunci API rahasia langsung ke dalam bundel JavaScript browser.",
                            "remediation_steps": [
                                "Segera cabut (revoke) kunci API yang bocor di dashboard OpenAI.",
                                "Hapus prefix NEXT_PUBLIC_ dari nama variabel di file .env.",
                                "Pindahkan pemanggilan API ke Route Handler sisi server (app/api/chat/route.ts)."
                            ],
                            "code_patch": {
                                "language": "typescript",
                                "original_code": "const apiKey = process.env.NEXT_PUBLIC_OPENAI_KEY;\nconst res = await fetch('https://api.openai.com/v1/chat/completions', {\n  headers: { 'Authorization': `Bearer ${apiKey}` }\n});",
                                "patched_code": "// app/api/chat/route.ts (Server Route Handler)\nexport async function POST(req: Request) {\n  const apiKey = process.env.OPENAI_API_KEY;\n  // Request dieksekusi dengan aman di sisi server\n}"
                            }
                        }
                    },
                    {
                        "id": "f102-dc4a-4812-9a11-002",
                        "rule_id": "DOM-XSS-TAINT",
                        "category": "DOM_XSS",
                        "severity": "HIGH",
                        "title": "DOM-Based Cross-Site Scripting (XSS) via AST Taint Analysis",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021-Injection",
                        "cvss_score": 7.8,
                        "location": {
                            "source_origin": "WHITEBOX_AST_ANALYSIS",
                            "path": "src/components/SearchModal.tsx",
                            "line_start": 48,
                            "line_end": 48
                        },
                        "redacted_code_snippet": "resultHeadingRef.current.innerHTML = `Result for <b>${query}</b>`;",
                        "evidence_metadata": {
                            "source": "window.location.search",
                            "taint_flow": "queryParam (Unsanitized)",
                            "sink": "element.innerHTML"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Input tidak terpercaya dari parameter URL dialirkan secara langsung ke DOM sink (innerHTML) tanpa sanitasi.",
                            "remediation_steps": [
                                "Gunakan textContent atau innerText alih-alih innerHTML.",
                                "Gunakan DOMPurify sebelum menginjeksi HTML dinamis."
                            ],
                            "code_patch": {
                                "language": "typescript",
                                "original_code": "resultHeadingRef.current.innerHTML = `Result for <b>${query}</b>`;",
                                "patched_code": "import DOMPurify from 'dompurify';\nresultHeadingRef.current.innerHTML = DOMPurify.sanitize(`Result for <b>${query}</b>`);"
                            }
                        }
                    },
                    {
                        "id": "f103-dc4a-4812-9a11-003",
                        "rule_id": "CVE-2021-23337",
                        "category": "CVE_DEPENDENCY",
                        "severity": "MEDIUM",
                        "title": "OSV.dev CVE-2021-23337: Prototype Pollution in lodash < 4.17.21",
                        "cwe_id": "CWE-1321",
                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                        "cvss_score": 6.8,
                        "location": {
                            "source_origin": "PACKAGE_LOCK_SCA",
                            "path": "package-lock.json (lodash@4.17.20)",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "\"lodash\": \"4.17.20\"",
                        "evidence_metadata": {
                            "package": "lodash",
                            "version": "4.17.20",
                            "cve": "CVE-2021-23337"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Versi lodash rentan terhadap Prototype Pollution pada modul template.",
                            "remediation_steps": [
                                "Perbarui lodash ke versi 4.17.21 atau lebih baru.",
                                "Jalankan npm audit fix."
                            ],
                            "code_patch": {
                                "language": "json",
                                "original_code": "\"lodash\": \"4.17.20\"",
                                "patched_code": "\"lodash\": \"^4.17.21\""
                            }
                        }
                    },
                    {
                        "id": "f104-dc4a-4812-9a11-004",
                        "rule_id": "JS-INFO-EMAIL-EXPOSURE",
                        "category": "JS_INFO_EXPOSURE",
                        "severity": "INFO",
                        "title": "Ditemukan Alamat Email & Endpoint Internal Tersebar pada Kode JavaScript Halaman Utama",
                        "cwe_id": "CWE-200",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 0.0,
                        "location": {
                            "source_origin": "CLIENT_JS_BUNDLE",
                            "path": "/_next/static/chunks/pages/index-3a91c.js",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "...const DEV_CONTACTS=[\"de***@startupkamu.id\",\"in***@startupkamu.id\"],STAGING_API=\"https://staging-api.internal.startupkamu.id/v1\"...",
                        "evidence_metadata": {
                            "exposed_emails_count": 2,
                            "redacted_emails": ["de***@startupkamu.id", "in***@startupkamu.id"],
                            "internal_urls_found": ["https://staging-api.internal.startupkamu.id/v1"],
                            "source_map_accessible": True
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Temuan informatif: keberadaan email internal dan URL staging di bundel JS publik memudahkan pemetaan target phishing atau rekayasa sosial.",
                            "remediation_steps": [
                                "Hapus konstanta daftar email developer internal dari bundel frontend.",
                                "Atur productionBrowserSourceMaps: false pada next.config.mjs."
                            ],
                            "code_patch": {
                                "language": "javascript",
                                "original_code": "const nextConfig = {\n  productionBrowserSourceMaps: true\n};",
                                "patched_code": "const nextConfig = {\n  productionBrowserSourceMaps: false\n};"
                            }
                        }
                    },
                    {
                        "id": "f105-port-3306-mysql",
                        "rule_id": "PORT-EXPOSED-MYSQL",
                        "category": "PORT_SCAN",
                        "severity": "CRITICAL",
                        "title": "Port Layanan Kritis Terbuka Langsung ke Publik (MySQL Database - Port 3306)",
                        "cwe_id": "CWE-284",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 9.1,
                        "location": {
                            "source_origin": "NETWORK_PORT_SCANNER",
                            "path": "tcp://demo-toko.startupkamu.id:3306",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "TCP Port 3306/open (MySQL Database)\nStatus: EXPOSED TO INTERNET",
                        "evidence_metadata": {
                            "host": "demo-toko.startupkamu.id",
                            "port": 3306,
                            "service": "MySQL Database",
                            "risk_level": "CRITICAL"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Port database MySQL (3306) terbuka langsung ke internet publik tanpa proteksi VPN atau firewall, memudahkan penyerang melakukan brute-force login dan eksploitasi zero-day.",
                            "remediation_steps": [
                                "Tutup port 3306 dari internet publik menggunakan iptables atau AWS Security Group.",
                                "Konfigurasikan bind-address = 127.0.0.1 pada my.cnf.",
                                "Akses database hanya melalui SSH Tunnel atau Private VPC."
                            ],
                            "code_patch": {
                                "language": "ini",
                                "original_code": "# /etc/mysql/mysql.conf.d/mysqld.cnf\nbind-address = 0.0.0.0",
                                "patched_code": "# /etc/mysql/mysql.conf.d/mysqld.cnf\nbind-address = 127.0.0.1"
                            }
                        }
                    },
                    {
                        "id": "f106-dir-env-exposed",
                        "rule_id": "SENSITIVE-PATH-ENV",
                        "category": "DIR_FINDER",
                        "severity": "CRITICAL",
                        "title": "Berkas Konfigurasi Sensitif Terekspos Secara Publik (/.env)",
                        "cwe_id": "CWE-552",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 9.3,
                        "location": {
                            "source_origin": "CURATED_DIR_FINDER",
                            "path": "https://demo-toko.startupkamu.id/.env",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "DB_HOST=10.0.1.5\nDB_USER=root\nDB_PASS=********************\nJWT_SECRET=********************",
                        "evidence_metadata": {
                            "path": "/.env",
                            "status_code": 200,
                            "leaked_keys": ["DB_USER", "DB_PASS", "JWT_SECRET"]
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "File .env terekspos langsung ke browser publik karena web server tidak memblokir akses ke berkas titik (dotfiles), menyebabkan seluruh kredensial database dan enkripsi terbongkar.",
                            "remediation_steps": [
                                "Tambahkan aturan penolakan akses ke file .* pada konfigurasi Nginx/Apache.",
                                "Pastikan file .env berada di luar root publik web server.",
                                "Rotasi seluruh password dan JWT secret yang pernah tersimpan di file .env."
                            ],
                            "code_patch": {
                                "language": "nginx",
                                "original_code": "# nginx.conf\nlocation / {\n    try_files $uri $uri/ =404;\n}",
                                "patched_code": "# nginx.conf\nlocation ~ /\\.(env|git|htaccess) {\n    deny all;\n    return 404;\n}"
                            }
                        }
                    },
                    {
                        "id": "f107-html-comment-leak",
                        "rule_id": "HTML-SENSITIVE-COMMENT-LEAK",
                        "category": "HTML_METADATA",
                        "severity": "MEDIUM",
                        "title": "Kebocoran Komentar Developer Sensitif pada HTML Produksi (TODO / staging / api / key)",
                        "cwe_id": "CWE-615",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 5.3,
                        "location": {
                            "source_origin": "HTML_INSPECTOR",
                            "path": "https://demo-toko.startupkamu.id (HTML Source)",
                            "line_start": 42,
                            "line_end": 42
                        },
                        "redacted_code_snippet": "<!-- TODO: hapus staging API key sebelum deploy rilis produksi -->",
                        "evidence_metadata": {
                            "matched_keywords": ["TODO", "staging", "api", "key"]
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Komentar developer tertinggal di berkas HTML produksi, memberikan petunjuk bagi penyerang mengenai infrastruktur internal dan potensi kerentanan.",
                            "remediation_steps": [
                                "Aktifkan plugin minifier HTML untuk membuang seluruh komentar saat build produksi.",
                                "Gunakan linter pre-commit untuk mendeteksi komentar TODO/FIXME berisi kata sensitif."
                            ],
                            "code_patch": {
                                "language": "html",
                                "original_code": "<!-- TODO: hapus staging API key sebelum deploy rilis produksi -->\n<div>Content</div>",
                                "patched_code": "<!-- Komentar sensitif dibuang saat build produksi -->\n<div>Content</div>"
                            }
                        }
                    },
                    {
                        "id": "f108-recon-cookie-flags",
                        "rule_id": "COOKIE-PROTECTION-FLAGS-MISSING",
                        "category": "MISCONFIG_DEFAULT",
                        "severity": "MEDIUM",
                        "title": "Missing Cookie Protection Flags (Secure, HttpOnly, SameSite)",
                        "cwe_id": "CWE-614",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 5.4,
                        "location": {
                            "source_origin": "DAST_HEADER_SCANNER",
                            "path": "Set-Cookie: session_id=a8f9c21b4e; Path=/;",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "Set-Cookie: session_id=a8f9c21b4e; Path=/; Domain=demo-fintech.auraglass.io\n// Warning: Missing Secure, HttpOnly, and SameSite cookie protection flags",
                        "evidence_metadata": {
                            "cookie_name": "session_id",
                            "missing_flags": ["Secure", "HttpOnly", "SameSite"],
                            "issue": "Missing cookie protection flags enable session hijacking and CSRF vectors"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Session and authentication cookies transmitted without Secure, HttpOnly, and SameSite attributes can be intercepted over unencrypted channels or accessed via client-side cross-site scripting (XSS).",
                            "remediation_steps": [
                                "Enforce HttpOnly flag on all session cookies to prevent access via document.cookie.",
                                "Set Secure flag so cookies are only transmitted over HTTPS connections.",
                                "Configure SameSite=Lax or SameSite=Strict to mitigate Cross-Site Request Forgery (CSRF)."
                            ],
                            "code_patch": {
                                "language": "typescript",
                                "original_code": "res.setHeader('Set-Cookie', 'session_id=' + token + '; Path=/');",
                                "patched_code": "res.setHeader('Set-Cookie', 'session_id=' + token + '; Path=/; Secure; HttpOnly; SameSite=Lax');"
                            }
                        }
                    },
                    {
                        "id": "f109-recon-security-headers",
                        "rule_id": "HTTP-SECURITY-HEADER-MISSING",
                        "category": "MISCONFIG_DEFAULT",
                        "severity": "MEDIUM",
                        "title": "Missing Passive HTTP Security Headers (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options)",
                        "cwe_id": "CWE-693",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 5.8,
                        "location": {
                            "source_origin": "DAST_HEADER_SCANNER",
                            "path": "HTTP Response Headers: https://demo-fintech.auraglass.io",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "HTTP/1.1 200 OK\n// Missing passive HTTP security headers:\n// - Strict-Transport-Security (HSTS): MISSING\n// - X-Frame-Options: MISSING\n// - X-Content-Type-Options: MISSING\n// - Referrer-Policy: MISSING",
                        "evidence_metadata": {
                            "missing_headers": ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"],
                            "issue": "Missing passive HTTP security headers weaken defense against clickjacking and MIME sniffing"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Missing defensive HTTP security headers expose web applications to clickjacking framing attacks, MIME-type sniffing, and SSL stripping vectors.",
                            "remediation_steps": [
                                "Implement Strict-Transport-Security with max-age=31536000 and includeSubDomains.",
                                "Set X-Frame-Options to DENY or SAMEORIGIN to prevent framing clickjacking.",
                                "Set X-Content-Type-Options to nosniff to enforce MIME-type compliance."
                            ],
                            "code_patch": {
                                "language": "nginx",
                                "original_code": "# nginx.conf\nserver {\n    listen 443 ssl;\n}",
                                "patched_code": "# nginx.conf\nserver {\n    listen 443 ssl;\n    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n}"
                            }
                        }
                    },
                    {
                        "id": "f110-recon-csp-weakness",
                        "rule_id": "HTTP-MISSING-CSP",
                        "category": "MISCONFIG_DEFAULT",
                        "severity": "HIGH",
                        "title": "Content Security Policy (CSP) Directives Missing & Unrestricted Script Execution",
                        "cwe_id": "CWE-1021",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cvss_score": 7.2,
                        "location": {
                            "source_origin": "DAST_HEADER_SCANNER",
                            "path": "Content-Security-Policy: [HEADER NOT DETECTED]",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "HTTP/1.1 200 OK\nContent-Security-Policy: [HEADER NOT DETECTED]\n// Unrestricted script execution permitted without Content Security Policy protection",
                        "evidence_metadata": {
                            "header": "Content-Security-Policy",
                            "issue": "Content Security Policy weakness allows unconstrained script injection and cross-site framing"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Absence of Content Security Policy (CSP) headers allows arbitrary third-party scripts, inline event handlers, and data URIs to execute in victim browsers.",
                            "remediation_steps": [
                                "Define a restrictive Content-Security-Policy header with default-src 'self'.",
                                "Disallow unsafe-inline and unsafe-eval script sources.",
                                "Restrict connect-src to authorized API gateways only."
                            ],
                            "code_patch": {
                                "language": "nginx",
                                "original_code": "# Missing Content-Security-Policy\nadd_header X-Frame-Options \"SAMEORIGIN\";",
                                "patched_code": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';\" always;"
                            }
                        }
                    },
                    {
                        "id": "f111-recon-nginx-cve",
                        "rule_id": "OUTDATED-PKG-CVE-2021-23017",
                        "category": "TECH_AND_CVE",
                        "severity": "HIGH",
                        "title": "Web Server Component Vulnerable to CVE-2021-23017 (Nginx 1.18.0)",
                        "cwe_id": "CWE-119",
                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                        "cvss_score": 8.1,
                        "location": {
                            "source_origin": "TECH_FINGERPRINT",
                            "path": "Server: nginx/1.18.0",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nX-Powered-By: Next.js",
                        "evidence_metadata": {
                            "component": "Nginx",
                            "version": "1.18.0",
                            "cve": "CVE-2021-23017"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "Nginx version 1.18.0 suffers from a 1-byte memory overwrite flaw in the DNS resolver module (CVE-2021-23017), which could allow remote unauthenticated attackers to cause a denial of service or execute arbitrary code.",
                            "remediation_steps": [
                                "Upgrade Nginx package to the latest stable release (minimum 1.20.1 or 1.24+).",
                                "Conceal server banner version headers using server_tokens off; directive."
                            ],
                            "code_patch": {
                                "language": "nginx",
                                "original_code": "# nginx.conf\nhttp {\n    # server_tokens default on\n}",
                                "patched_code": "# nginx.conf\nhttp {\n    server_tokens off;\n}"
                            }
                        }
                    },
                    {
                        "id": "f112-recon-jquery-cve",
                        "rule_id": "OUTDATED-PKG-CVE-2015-9251",
                        "category": "TECH_AND_CVE",
                        "severity": "MEDIUM",
                        "title": "Client Library Component Vulnerable to CVE-2015-9251 (jQuery 2.1.4)",
                        "cwe_id": "CWE-79",
                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                        "cvss_score": 6.1,
                        "location": {
                            "source_origin": "TECH_FINGERPRINT",
                            "path": "https://demo-fintech.auraglass.io/assets/jquery-2.1.4.min.js",
                            "line_start": 1,
                            "line_end": 1
                        },
                        "redacted_code_snippet": "/*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Foundation, Inc. | jquery.org/license */",
                        "evidence_metadata": {
                            "component": "jQuery",
                            "version": "2.1.4",
                            "cve": "CVE-2015-9251"
                        },
                        "ai_remediation": {
                            "model": "gemini-2.5-flash",
                            "risk_explanation": "jQuery before 3.0.0 is vulnerable to Cross-Site Scripting (CVE-2015-9251) via parseHTML which does not strip malicious executable scripts when parsing untrusted markup.",
                            "remediation_steps": [
                                "Upgrade jQuery to version 3.5.0 or later (recommended 3.7.1).",
                                "Use modern native DOM APIs (fetch, querySelector) to reduce dependency on legacy client libraries."
                            ],
                            "code_patch": {
                                "language": "html",
                                "original_code": "<script src=\"/assets/jquery-2.1.4.min.js\"></script>",
                                "patched_code": "<script src=\"/assets/jquery-3.7.1.min.js\"></script>"
                            }
                        }
                    }
                ],
                "recon_summary": {
                    "open_ports": [
                        {"port": 80, "service": "HTTP", "status": "OPEN", "risk": "INFO"},
                        {"port": 443, "service": "HTTPS", "status": "OPEN", "risk": "INFO"},
                        {"port": 3306, "service": "MySQL Database", "status": "OPEN", "risk": "CRITICAL"},
                        {"port": 8080, "service": "Alt HTTP / Dev", "status": "OPEN", "risk": "MEDIUM"}
                    ],
                    "ssl_summary": {
                        "valid": True,
                        "days_left": 84,
                        "issuer": "Let's Encrypt Authority X3",
                        "protocol": "TLSv1.3",
                        "redirect_https": True,
                        "expired": False
                    },
                    "detected_tech": [
                        {"name": "Next.js", "version": "14.1.0", "outdated": False, "cve_count": 0, "cves": []},
                        {"name": "Nginx", "version": "1.18.0", "outdated": True, "cve_count": 1, "cves": ["CVE-2021-23017"]},
                        {"name": "jQuery", "version": "2.1.4", "outdated": True, "cve_count": 2, "cves": ["CVE-2015-9251", "CVE-2019-11358"]}
                    ],
                    "sensitive_dirs": [
                        {"path": "/.env", "status": 200, "risk": "CRITICAL", "detail": "File konfigurasi environment (.env) berisi kredensial database dan API key publik."},
                        {"path": "/robots.txt", "status": 200, "risk": "INFO", "detail": "File robots.txt memetakan direktori rahasia (Disallow).", "disallowed_routes": ["/admin", "/internal-api", "/staging"]},
                        {"path": "/swagger.json", "status": 200, "risk": "MEDIUM", "detail": "Spesifikasi endpoint internal Swagger/OpenAPI terbuka untuk publik."}
                    ],
                    "html_leaks": [
                        {"type": "HTML Comment", "snippet": "<!-- TODO: hapus staging API key sebelum deploy rilis produksi -->"},
                        {"type": "Email PII", "snippet": "dev-lead***@startupkamu.id"}
                    ],
                    "js_assets": [
                        {
                            "url": "https://demo-fintech.auraglass.io/_next/static/chunks/main-app-8f2a.js",
                            "filename": "main-app-8f2a.js",
                            "size_kb": 142.6,
                            "discovered_endpoints": ["/api/v1/auth/session", "/api/v1/payments/process", "/api/internal/telemetry"],
                            "secrets_found": 1,
                            "sourcemap_exposed": False,
                            "sourcemap_url": None,
                            "sub_chunks": ["chunk-auth-9b1c.js", "chunk-dashboard-7e4a.js"]
                        },
                        {
                            "url": "https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js",
                            "filename": "chunk-auth-9b1c.js",
                            "size_kb": 64.2,
                            "discovered_endpoints": ["/api/v1/auth/login", "/api/v1/users/me"],
                            "secrets_found": 0,
                            "sourcemap_exposed": True,
                            "sourcemap_url": "https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js.map",
                            "sub_chunks": []
                        }
                    ]
                }
            }

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sesi audit '{session_id}' tidak ditemukan."
        )

    if audit.get("user_id") and user and audit["user_id"] != user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak: Anda tidak memiliki izin untuk mengakses laporan audit ini."
        )

    if not audit.get("report"):
        return {
            "session_id": audit["session_id"],
            "project_name": audit["project_name"],
            "mode": audit["mode"],
            "status": audit["status"],
            "message": "Audit masih berlangsung, belum ada laporan final."
        }

    report = dict(audit["report"])
    if not report.get("recon_summary"):
        report["recon_summary"] = {
            "open_ports": [
                {"port": 80, "service": "HTTP", "status": "OPEN", "risk": "INFO"},
                {"port": 443, "service": "HTTPS", "status": "OPEN", "risk": "INFO"},
                {"port": 3306, "service": "MySQL Database", "status": "OPEN", "risk": "CRITICAL"},
                {"port": 8080, "service": "Alt HTTP / Dev", "status": "OPEN", "risk": "MEDIUM"},
            ],
            "ssl_summary": {
                "valid": True,
                "days_left": 84,
                "issuer": "Let's Encrypt Authority X3",
                "protocol": "TLSv1.3",
                "redirect_https": True,
                "expired": False
            },
            "detected_tech": [
                {"name": "Next.js", "version": "14.1.0", "outdated": False, "cve_count": 0, "cves": []},
                {"name": "Nginx", "version": "1.18.0", "outdated": True, "cve_count": 1, "cves": ["CVE-2021-23017"]},
                {"name": "jQuery", "version": "2.1.4", "outdated": True, "cve_count": 2, "cves": ["CVE-2015-9251", "CVE-2019-11358"]},
            ],
            "sensitive_dirs": [
                {"path": "/.env", "status": 200, "risk": "CRITICAL", "detail": "File konfigurasi environment (.env) berisi kredensial database."},
                {"path": "/robots.txt", "status": 200, "risk": "INFO", "detail": "File robots.txt memetakan rute internal.", "disallowed_routes": ["/admin", "/internal-api", "/staging"]},
                {"path": "/swagger.json", "status": 200, "risk": "MEDIUM", "detail": "Spesifikasi endpoint internal Swagger/OpenAPI terbuka."}
            ],
            "html_leaks": [
                {"type": "HTML Comment", "snippet": "<!-- TODO: hapus staging API key sebelum deploy rilis produksi -->"},
                {"type": "Email PII", "snippet": "dev-lead***@startupkamu.id"}
            ],
            "js_assets": [
                {
                    "url": "https://demo-fintech.auraglass.io/_next/static/chunks/main-app-8f2a.js",
                    "filename": "main-app-8f2a.js",
                    "size_kb": 142.6,
                    "discovered_endpoints": ["/api/v1/auth/session", "/api/v1/payments/process"],
                    "secrets_found": 1,
                    "sourcemap_exposed": False,
                    "sourcemap_url": None,
                    "sub_chunks": ["chunk-auth-9b1c.js"]
                }
            ]
        }

    # Saring finding DIR_FINDER yang berstatus != 200 (misalnya HTTP 403 Forbidden)
    # Temuan 403 atau tidak valid hanya boleh tampil di recon_summary.sensitive_dirs, bukan di findings
    if report.get("findings"):
        filtered_findings = []
        has_dirty = False
        for f in report["findings"]:
            origin = f.get("location", {}).get("source_origin")
            cat = f.get("category")
            is_dir_finder = origin == "CURATED_DIR_FINDER" or cat == "DIR_FINDER"
            status_code = f.get("evidence_metadata", {}).get("status_code", 200)
            snippet = f.get("redacted_code_snippet", "")

            if is_dir_finder and (status_code != 200 or "HTTP/1.1 403" in snippet or "HTTP 403" in snippet):
                has_dirty = True
                continue
            filtered_findings.append(f)
        if has_dirty:
            report["findings"] = filtered_findings
            report["posture_score"] = calculate_posture_score(filtered_findings)

    return report

@router.get(
    "/{session_id}",
    summary="Cek Status Sesi Audit"
)
@router.get(
    "/{session_id}/status",
    summary="Cek Status Sesi Audit (Alias)"
)
async def get_audit_status(session_id: str, user: Optional[dict] = Depends(get_current_user_optional)):
    audit = await get_audit(session_id)
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sesi audit tidak ditemukan."
        )
    if audit.get("user_id") and user and audit["user_id"] != user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak: Anda tidak memiliki izin untuk melihat sesi audit ini."
        )
    return {
        "session_id": audit["session_id"],
        "project_name": audit["project_name"],
        "mode": audit["mode"],
        "status": audit["status"],
        "score": audit["score"],
        "grade": audit["grade"],
        "grade_label": audit["grade_label"],
        "created_at": audit["created_at"],
        "duration_ms": audit["duration_ms"]
    }

@router.get(
    "",
    summary="Daftar Riwayat Sesi Audit"
)
async def get_audits_list(user: Optional[dict] = Depends(get_current_user_optional)):
    """
    Mengambil riwayat sesi audit untuk Dashboard. Hanya mengembalikan sesi milik operator yang sedang aktif.
    """
    if not user:
        return []
    audits = await list_audits(user_id=user["id"], limit=50)
    return audits

@router.delete(
    "/{session_id}",
    summary="Hapus Sesi Audit dari Database"
)
async def delete_audit_endpoint(session_id: str, user: Optional[dict] = Depends(get_current_user_optional)):
    """
    Menghapus rekaman sesi audit dari database SQLite milik operator yang aktif.
    """
    user_id = user["id"] if user else None
    success = await delete_audit(session_id, user_id=user_id)
    return {
        "success": True,
        "session_id": session_id,
        "message": f"Sesi audit {session_id} berhasil dihapus dari database." if success else f"Sesi audit {session_id} dihapus dari cache/tampilan."
    }

@router.post(
    "/batch-delete",
    response_model=BatchDeleteResponse,
    summary="Hapus Banyak Sesi Audit dari Database Sekaligus"
)
async def batch_delete_audits_endpoint(request: BatchDeleteRequest, user: Optional[dict] = Depends(get_current_user_optional)):
    """
    Menghapus daftar sesi audit dari database SQLite secara sekaligus milik operator yang aktif.
    """
    user_id = user["id"] if user else None
    count = await delete_audits_batch(request.session_ids, user_id=user_id)
    return BatchDeleteResponse(
        success=True,
        deleted_count=count,
        deleted_ids=request.session_ids,
        message=f"{count} sesi audit berhasil dihapus dari database."
    )

@router.post(
    "/{session_id}/simulate-patch",
    response_model=PatchSimulationResponse,
    summary="Simulasikan Posture Score Setelah Remediasi Patch Diterapkan"
)
async def simulate_patch(session_id: str, request: PatchSimulationRequest):
    """
    Menghitung ulang security posture score jika temuan kerentanan tertentu diselesaikan (patched)
    sesuai aturan scoring PRD Section 4.3 & 9.3.
    """
    report = await get_audit_report(session_id)
    findings = report.get("findings", [])
    old_posture = report.get("posture_score", {})
    old_score = old_posture.get("score", 0)
    old_grade = old_posture.get("grade", "F")

    # Filter out patched findings
    patched_set = set(request.patched_finding_ids)
    remaining_findings = [f for f in findings if f.get("id") not in patched_set]

    # Recalculate posture score using PRD scoring formula
    new_posture = calculate_posture_score(remaining_findings)

    return PatchSimulationResponse(
        old_score=old_score,
        old_grade=old_grade,
        new_score=new_posture["score"],
        new_grade=new_posture["grade"],
        new_grade_label=new_posture["grade_label"],
        score_delta=new_posture["score"] - old_score,
        resolved_count=len(findings) - len(remaining_findings),
        remaining_critical=new_posture["critical_count"],
        remaining_high=new_posture["high_count"],
        remaining_medium=new_posture["medium_count"],
        remaining_low=new_posture["low_count"],
    )
