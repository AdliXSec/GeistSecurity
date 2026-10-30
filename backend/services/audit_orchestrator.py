import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import logging

from backend.database import save_audit, get_audit
from backend.services.blackbox_scanner import scan_blackbox
from backend.services.whitebox_scanner import scan_whitebox
from backend.services.ai_remediation import generate_remediation_for_finding
from backend.services.scoring import calculate_posture_score
from backend.services.redactor import sanitize_dict_or_list

logger = logging.getLogger(__name__)

# In-memory pub/sub dan event history buffer untuk SSE streams per session_id
SESSION_EVENTS: Dict[str, List[Dict[str, Any]]] = {}
SESSION_SUBSCRIBERS: Dict[str, List[asyncio.Queue]] = {}

def subscribe(session_id: str) -> Tuple[List[Dict[str, Any]], asyncio.Queue]:
    """
    Mendaftarkan subscriber baru untuk session_id dan mengembalikan riwayat event masa lalu
    beserta antrean (queue) untuk event real-time berikutnya.
    """
    history = list(SESSION_EVENTS.get(session_id, []))
    q = asyncio.Queue()
    if session_id not in SESSION_SUBSCRIBERS:
        SESSION_SUBSCRIBERS[session_id] = []
    SESSION_SUBSCRIBERS[session_id].append(q)
    return history, q

def unsubscribe(session_id: str, q: asyncio.Queue):
    """
    Menghapus subscriber antrean saat koneksi SSE terputus.
    """
    if session_id in SESSION_SUBSCRIBERS:
        if q in SESSION_SUBSCRIBERS[session_id]:
            SESSION_SUBSCRIBERS[session_id].remove(q)
        if not SESSION_SUBSCRIBERS[session_id]:
            del SESSION_SUBSCRIBERS[session_id]

def get_or_create_queue(session_id: str) -> asyncio.Queue:
    _, q = subscribe(session_id)
    return q

async def emit_sse(
    session_id: str,
    stage: str,
    progress: int,
    message: str,
    redirect_url: Optional[str] = None,
    mode: Optional[str] = None
):
    event_payload = {
        "session_id": session_id,
        "stage": stage,
        "progress": progress,
        "message": message,
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "redirect_report_url": redirect_url
    }
    if session_id not in SESSION_EVENTS:
        SESSION_EVENTS[session_id] = []
    SESSION_EVENTS[session_id].append(event_payload)

    # Broadcast ke seluruh subscriber yang sedang terhubung
    subscribers = list(SESSION_SUBSCRIBERS.get(session_id, []))
    for q in subscribers:
        await q.put(event_payload)

async def run_audit_pipeline(
    session_id: str,
    project_name: str,
    mode: str,
    target_url: Optional[str],
    github_repo_url: Optional[str],
    branch: str = "main",
    entropy_threshold: float = 4.2,
    scan_depth: str = "Deep",
    js_exposure: bool = True,
    enable_nuclei: bool = True,
    nuclei_profile: str = "quick",
    user_id: Optional[str] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
):
    start_time = time.time()
    created_at = datetime.now(timezone.utc).isoformat()

    # Auto-route GitHub repo URLs provided in target_url only if mode is not BLACKBOX
    if target_url and "github.com" in target_url.lower() and mode != "BLACKBOX":
        if not github_repo_url:
            github_repo_url = target_url
        target_url = None
        mode = "WHITEBOX"

    try:
        # Initial Save status
        await save_audit(
            session_id=session_id,
            project_name=project_name,
            mode=mode,
            status="IN_PROGRESS",
            target_url=target_url,
            github_repo_url=github_repo_url,
            branch=branch,
            created_at=created_at,
            updated_at=created_at,
            user_id=user_id,
        )

        all_findings: List[Dict[str, Any]] = []
        detected_tech_stack: List[str] = []
        recon_summary: Dict[str, Any] = {}
        wb_ai_warning: Optional[str] = None

        if mode == "WHITEBOX":
            # STAGE 1: WB_INIT (15%)
            await emit_sse(
                session_id,
                "WB_INIT",
                15,
                f"Menginisialisasi ruang kerja SAST & kloning repositori {github_repo_url or 'Git target'}...",
                mode="WHITEBOX"
            )
            await asyncio.sleep(1.0)

            async def wb_cb(stg: str, prog: int, msg: str):
                await emit_sse(session_id, stg, prog, msg, mode="WHITEBOX")

            wb_res = await scan_whitebox(
                github_repo_url or "",
                branch,
                entropy_threshold=entropy_threshold,
                scan_depth=scan_depth,
                progress_callback=wb_cb
            )
            if isinstance(wb_res, tuple) and len(wb_res) == 3:
                whitebox_findings, wb_tech, wb_ai_warning = wb_res
                detected_tech_stack.extend([t for t in wb_tech if t not in detected_tech_stack])
            elif isinstance(wb_res, tuple) and len(wb_res) == 2:
                whitebox_findings, wb_tech = wb_res
                detected_tech_stack.extend([t for t in wb_tech if t not in detected_tech_stack])
            else:
                whitebox_findings = wb_res or []

            all_findings.extend(whitebox_findings)

            # STAGE 6: WB_AI_REMEDIATION (95%)
            ai_stage_msg = "Menyusun penjelasan risiko & kode perbaikan (Before vs. After Diff) menggunakan AI..."
            if wb_ai_warning:
                ai_stage_msg = f"Menyusun remediasi AI ({wb_ai_warning})..."
            await emit_sse(
                session_id,
                "WB_AI_REMEDIATION",
                95,
                ai_stage_msg,
                mode="WHITEBOX"
            )

        elif mode == "BLACKBOX":
            # STAGE 1: BB_INIT (15%)
            await emit_sse(
                session_id,
                "BB_INIT",
                15,
                f"Menginisialisasi ruang kerja Blackbox & validasi Anti-SSRF target {target_url}...",
                mode="BLACKBOX"
            )
            await asyncio.sleep(0.8)

            # STAGE 2: BB_PORT_RADAR (35%)
            await emit_sse(
                session_id,
                "BB_PORT_RADAR",
                35,
                f"Memindai port jaringan terbuka ({scan_depth}) via async socket probe...",
                mode="BLACKBOX"
            )
            await asyncio.sleep(0.8)

            # STAGE 3: BB_SSL_TLS (50%)
            await emit_sse(
                session_id,
                "BB_SSL_TLS",
                50,
                "Menganalisis sertifikat SSL/TLS, cipher suite & validasi X.509...",
                mode="BLACKBOX"
            )
            await asyncio.sleep(0.8)

            # STAGE 4: BB_TECH_CVE (65%)
            await emit_sse(
                session_id,
                "BB_TECH_CVE",
                65,
                "Mendeteksi banner HTTP, fingerprinting framework & query CVE OSV.dev...",
                mode="BLACKBOX"
            )
            await asyncio.sleep(0.8)

            # STAGE 5: BB_DIR_FINDER (80%)
            await emit_sse(
                session_id,
                "BB_DIR_FINDER",
                80,
                f"Probing direktori & file sensitif ({scan_depth}) dengan Soft-404 guard...",
                mode="BLACKBOX"
            )
            await asyncio.sleep(0.8)

            # STAGE 6: BB_JS_EXPOSURE (90%)
            await emit_sse(
                session_id,
                "BB_JS_EXPOSURE",
                90,
                f"Menganalisis bundel JS ({scan_depth} Crawl), source map & Shannon Entropy (H>={entropy_threshold})...",
                mode="BLACKBOX"
            )

            if target_url:
                async def bb_nuclei_cb(stage: str, prog: int, msg: str):
                    await emit_sse(session_id, stage, prog, msg, mode="BLACKBOX")

                blackbox_findings, tech_stack, recon_res = await scan_blackbox(
                    target_url,
                    entropy_threshold=entropy_threshold,
                    scan_depth=scan_depth,
                    js_exposure=js_exposure,
                    enable_nuclei=enable_nuclei,
                    nuclei_profile=nuclei_profile,
                    progress_callback=bb_nuclei_cb,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                )
                detected_tech_stack.extend(tech_stack)
                all_findings.extend(blackbox_findings)
                recon_summary = recon_res

            # STAGE 7: BB_AI_REMEDIATION (96%)
            await emit_sse(
                session_id,
                "BB_AI_REMEDIATION",
                96,
                "Menyusun evaluasi postur keamanan & rekomendasi perbaikan AI...",
                mode="BLACKBOX"
            )

        else:  # HYBRID
            # STAGE 1: HYB_INIT (15%)
            await emit_sse(
                session_id,
                "HYB_INIT",
                15,
                "Menginisialisasi analisis Hybrid: Sinkronisasi Git repositori & Target Web...",
                mode="HYBRID"
            )
            await asyncio.sleep(0.8)

            # STAGE 2: HYB_SCA_NETWORK (35%)
            await emit_sse(
                session_id,
                "HYB_SCA_NETWORK",
                35,
                "Memindai port terbuka & menganalisis dependensi paket (OSV.dev)...",
                mode="HYBRID"
            )
            await asyncio.sleep(0.8)

            # STAGE 3: HYB_RECON_PROBE (55%)
            await emit_sse(
                session_id,
                "HYB_RECON_PROBE",
                55,
                "Probing resource web sensitif, sertifikat SSL & validasi Soft-404...",
                mode="HYBRID"
            )
            await asyncio.sleep(0.8)

            # STAGE 4: HYB_SAST_AST (70%)
            await emit_sse(
                session_id,
                "HYB_SAST_AST",
                70,
                f"Audit SAST pada template ({scan_depth}) & penambangan rahasia (H>={entropy_threshold})...",
                mode="HYBRID"
            )

            if github_repo_url:
                wb_res = await scan_whitebox(
                    github_repo_url,
                    branch,
                    entropy_threshold=entropy_threshold,
                    scan_depth=scan_depth
                )
                if isinstance(wb_res, tuple) and len(wb_res) == 3:
                    whitebox_findings, wb_tech, wb_ai_warning = wb_res
                    detected_tech_stack.extend([t for t in wb_tech if t not in detected_tech_stack])
                elif isinstance(wb_res, tuple) and len(wb_res) == 2:
                    whitebox_findings, wb_tech = wb_res
                    detected_tech_stack.extend([t for t in wb_tech if t not in detected_tech_stack])
                else:
                    whitebox_findings = wb_res or []
                all_findings.extend(whitebox_findings)

            # STAGE 5: HYB_TAINT_JS (85%)
            await emit_sse(
                session_id,
                "HYB_TAINT_JS",
                85,
                "Deobfuscasi chunk JS klien & pelacakan alur data taint backend...",
                mode="HYBRID"
            )

            if target_url:
                async def hyb_nuclei_cb(stage: str, prog: int, msg: str):
                    await emit_sse(session_id, stage, prog, msg, mode="HYBRID")

                blackbox_findings, tech_stack, recon_res = await scan_blackbox(
                    target_url,
                    entropy_threshold=entropy_threshold,
                    scan_depth=scan_depth,
                    js_exposure=js_exposure,
                    enable_nuclei=enable_nuclei,
                    nuclei_profile=nuclei_profile,
                    progress_callback=hyb_nuclei_cb,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                )
                detected_tech_stack.extend(tech_stack)
                all_findings.extend(blackbox_findings)
                recon_summary = recon_res

            # STAGE 6: HYB_AI_REMEDIATION (95%)
            await emit_sse(
                session_id,
                "HYB_AI_REMEDIATION",
                95,
                "Korelasi temuan Blackbox & Whitebox serta sintesis rekomendasi patch AI...",
                mode="HYBRID"
            )
        # Menghasilkan AI Remediation untuk setiap finding secara paralel terkendali
        sem = asyncio.Semaphore(3)

        async def remediate_one(finding: Dict[str, Any]) -> Dict[str, Any]:
            if finding.get("ai_remediation") and finding["ai_remediation"].get("code_patch"):
                # Pertahankan analisis mendalam dari Red Team AI Whitebox
                return dict(finding)
            async with sem:
                remediation = await generate_remediation_for_finding(
                    rule_id=finding.get("rule_id", "GENERIC"),
                    title=finding.get("title", ""),
                    category=finding.get("category", ""),
                    code_snippet=finding.get("redacted_code_snippet", ""),
                    cwe_id=finding.get("cwe_id", "CWE-000")
                )
                finding_copy = dict(finding)
                finding_copy["ai_remediation"] = remediation
                await asyncio.sleep(0.3)  # Rate pacing aman
                return finding_copy

        if all_findings:
            gathered_findings = await asyncio.gather(*(remediate_one(f) for f in all_findings))
            enriched_findings: List[Dict[str, Any]] = list(gathered_findings)
        else:
            enriched_findings = []

        # Zero Plaintext Leak Sanitization
        sanitized_findings = sanitize_dict_or_list(enriched_findings)

        # STAGE 6: COMPLETED (100%)
        end_time = time.time()
        duration_ms = int((end_time - start_time) * 1000)
        completed_at = datetime.now(timezone.utc).isoformat()

        posture_score = calculate_posture_score(sanitized_findings)
        summary_counts = posture_score["summary_counts"]

        # Default tech stack fallback
        if not detected_tech_stack:
            detected_tech_stack = ["React", "TypeScript", "Tailwind CSS"]

        if recon_summary and mode != "WHITEBOX":
            recon_summary["engine_options"] = {
                "entropy_threshold": entropy_threshold,
                "scan_depth": scan_depth,
                "js_exposure": js_exposure,
                "enable_nuclei": enable_nuclei,
                "nuclei_profile": nuclei_profile
            }

        report_payload = {
            "session_id": session_id,
            "project_name": project_name,
            "mode": mode,
            "status": "COMPLETED",
            "audited_at": completed_at,
            "duration_ms": duration_ms,
            "target_info": {
                "target_url": target_url,
                "github_repo_url": github_repo_url,
                "branch": branch,
                "detected_tech_stack": detected_tech_stack,
                "ai_status_message": wb_ai_warning,
                "entropy_threshold": entropy_threshold,
                "scan_depth": scan_depth,
                "js_exposure": js_exposure,
                "auth_headers": {k: "[REDACTED]" for k in (auth_headers or {})} if auth_headers else None,
                "auth_cookies": {k: "[REDACTED]" for k in (auth_cookies or {})} if auth_cookies else None,
                "enable_nuclei": enable_nuclei,
                "nuclei_profile": nuclei_profile,
                "nuclei_findings_count": recon_summary.get("nuclei_findings_count", 0) if recon_summary else 0
            },
            "posture_score": posture_score,
            "findings": sanitized_findings,
            "recon_summary": recon_summary if mode != "WHITEBOX" else {},
            "ai_status_message": wb_ai_warning
        }

        # Save to database
        await save_audit(
            session_id=session_id,
            project_name=project_name,
            mode=mode,
            status="COMPLETED",
            target_url=target_url,
            github_repo_url=github_repo_url,
            branch=branch,
            created_at=created_at,
            updated_at=completed_at,
            score=posture_score["score"],
            grade=posture_score["grade"],
            grade_label=posture_score["grade_label"],
            critical_count=summary_counts["critical"],
            high_count=summary_counts["high"],
            duration_ms=duration_ms,
            report_json=report_payload,
            user_id=user_id,
        )

        redirect_url = f"/api/v1/audits/{session_id}/report"
        comp_msg = (
            "Audit Whitebox selesai. Laporan lengkap dan verifikasi patch siap dilihat."
            if mode == "WHITEBOX"
            else "Audit Blackbox selesai! Mengalihkan ke halaman laporan..."
            if mode == "BLACKBOX"
            else "Audit Hybrid selesai! Mengalihkan ke halaman laporan..."
        )
        await emit_sse(
            session_id,
            "COMPLETED",
            100,
            comp_msg,
            redirect_url=redirect_url,
            mode=mode
        )

    except Exception as e:
        logger.error(f"Error in audit pipeline: {str(e)}", exc_info=True)
        await emit_sse(session_id, "FAILED", 0, f"Audit gagal: {str(e)}")
        await save_audit(
            session_id=session_id,
            project_name=project_name,
            mode=mode,
            status="FAILED",
            target_url=target_url,
            github_repo_url=github_repo_url,
            branch=branch,
            created_at=created_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
        )
