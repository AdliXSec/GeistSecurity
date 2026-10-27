from typing import List, Dict, Any, Tuple, Optional, Callable, Awaitable
from urllib.parse import urlparse
import asyncio
import logging
from backend.services.recon_engine import run_comprehensive_recon
from backend.services.nuclei_scanner import run_nuclei_scan

logger = logging.getLogger(__name__)

def normalize_path(url: str) -> str:
    """Normalisasi URL path untuk pencocokan deduplikasi."""
    try:
        p = urlparse(url)
        path = p.path.rstrip("/")
        return path if path else "/"
    except Exception:
        return url

def deduplicate_and_merge_findings(
    recon_findings: List[Dict[str, Any]],
    nuclei_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Menggabungkan temuan dari Recon Bawaan dan Nuclei Engine secara cerdas.
    Mencegah duplikasi temuan (misalnya .env, .git, atau header yang sama)
    sekaligus memperkaya bukti (evidence metadata, curl command, dan matcher name).
    """
    merged: List[Dict[str, Any]] = []
    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    recon_map: Dict[str, Dict[str, Any]] = {}
    for rf in recon_findings:
        loc = rf.get("location") or {}
        raw_path = loc.get("path") or ""
        norm_path = normalize_path(raw_path).lower()
        rule_id = str(rf.get("rule_id", "")).upper()
        cat = str(rf.get("category", "")).upper()

        key = None
        if "DIR_SENSITIVE" in rule_id or "BACKUP" in cat or "CREDENTIAL" in cat:
            key = f"path:{norm_path}"
        elif "HSTS" in rule_id:
            key = "header:hsts"
        elif "CSP" in rule_id:
            key = "header:csp"
        elif "CLICKJACKING" in rule_id or "X-FRAME" in rule_id:
            key = "header:clickjacking"
        elif "CONTENT_TYPE" in rule_id:
            key = "header:content_type"
        elif "CORS" in rule_id:
            key = "header:cors"

        if key:
            recon_map[key] = rf
        else:
            merged.append(rf)

    nuclei_matched_keys = set()
    for nf in nuclei_findings:
        loc = nf.get("location") or {}
        raw_path = loc.get("path") or ""
        norm_path = normalize_path(raw_path).lower()
        rule_id = str(nf.get("rule_id", "")).lower()

        key = None
        if any(w in rule_id for w in ["env", "git", "backup", "sourcemap", "actuator", "swagger", "adminer"]):
            key = f"path:{norm_path}"
        elif "hsts" in rule_id:
            key = "header:hsts"
        elif "csp" in rule_id:
            key = "header:csp"
        elif "x-frame" in rule_id or "clickjacking" in rule_id:
            key = "header:clickjacking"
        elif "cors" in rule_id:
            key = "header:cors"

        if key and key in recon_map:
            # Duplikasi terdeteksi: perkaya temuan recon dengan metadata Nuclei
            rf = recon_map[key]
            nuclei_matched_keys.add(key)

            rf_sev = rf.get("severity", "MEDIUM").upper()
            nf_sev = nf.get("severity", "MEDIUM").upper()
            if sev_rank.get(nf_sev, 3) > sev_rank.get(rf_sev, 3):
                rf["severity"] = nf_sev
                rf["cvss_score"] = nf.get("cvss_score", rf.get("cvss_score"))

            rf_meta = dict(rf.get("evidence_metadata") or {})
            nf_meta = dict(nf.get("evidence_metadata") or {})
            rf_meta["nuclei_template_id"] = nf_meta.get("template_id")
            rf_meta["nuclei_matcher_name"] = nf_meta.get("matcher_name")
            if nf_meta.get("curl_command"):
                rf_meta["curl_command"] = nf_meta.get("curl_command")
                rf["redacted_code_snippet"] = nf_meta.get("curl_command")

            rf["evidence_metadata"] = rf_meta
            if "location" in rf:
                rf["location"]["source_origin"] = "RECON_AND_NUCLEI"
                rf["location"]["verified_by_nuclei"] = True

            desc = rf.get("description", "")
            t_id = nf_meta.get("template_id", "")
            if "Nuclei Engine" not in desc and t_id:
                rf["description"] = f"{desc} (Terkonfirmasi validasi template Nuclei: {t_id})"

            merged.append(rf)
        else:
            merged.append(nf)

    # Tambahkan sisa recon temuan yang tidak overlap
    for key, rf in recon_map.items():
        if key not in nuclei_matched_keys:
            merged.append(rf)

    return merged

async def scan_blackbox(
    target_url: str,
    entropy_threshold: float = 4.2,
    scan_depth: str = "Deep",
    js_exposure: bool = True,
    enable_nuclei: bool = True,
    nuclei_profile: str = "quick",
    progress_callback: Optional[Callable[[str, int, str], Awaitable[None]]] = None
) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, Any]]:
    """
    Menjalankan audit reconnaissance & blackbox surface attack comprehensive (7 modul bawaan + Nuclei curated engine).
    Mengembalikan (findings, detected_tech_names, recon_summary).
    """
    if not target_url:
        return [], [], {}

    recon_task = run_comprehensive_recon(
        target_url,
        entropy_threshold=entropy_threshold,
        scan_depth=scan_depth,
        js_exposure=js_exposure
    )

    nuclei_findings: List[Dict[str, Any]] = []

    if enable_nuclei:
        try:
            profile_name = "full" if scan_depth.lower() == "deep" else nuclei_profile
            nuclei_task = run_nuclei_scan(
                target_url,
                scan_profile=profile_name,
                progress_callback=progress_callback
            )
            recon_data, nuclei_findings = await asyncio.gather(recon_task, nuclei_task)
        except Exception as e:
            logger.error(f"[Blackbox] Error running parallel nuclei scan: {e}")
            recon_data = await recon_task
    else:
        recon_data = await recon_task

    recon_findings = recon_data.get("findings", [])
    findings = deduplicate_and_merge_findings(recon_findings, nuclei_findings)

    # Ekstrak nama tech stack
    tech_stack_names: List[str] = []
    for t in recon_data.get("detected_tech", []):
        name = t.get("name", "")
        ver = t.get("version")
        if name:
            tech_stack_names.append(f"{name} {ver}" if ver else name)

    recon_summary = {
        "open_ports": recon_data.get("open_ports", []),
        "ssl_summary": recon_data.get("ssl_summary", {}),
        "detected_tech": recon_data.get("detected_tech", []),
        "sensitive_dirs": recon_data.get("sensitive_dirs", []),
        "html_leaks": recon_data.get("html_leaks", []),
        "js_assets": recon_data.get("js_assets", []),
        "nuclei_findings_count": len(nuclei_findings),
        "enable_nuclei": enable_nuclei,
        "nuclei_profile": nuclei_profile
    }

    return findings, list(set(tech_stack_names)), recon_summary
