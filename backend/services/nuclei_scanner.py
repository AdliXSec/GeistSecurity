"""
Nuclei Scanner Service for SecAudit
Mengintegrasikan Nuclei CLI engine dengan curated templates untuk audit celah keamanan web.
"""

import asyncio
import json
import logging
import os
import shutil
import uuid
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Awaitable

logger = logging.getLogger(__name__)

# Direktori template kurasi Nuclei (secara default di backend/rules/nuclei)
_DEFAULT_NUCLEI_DIR = Path(__file__).resolve().parent.parent / "rules" / "nuclei"
CURATED_TEMPLATES_DIR = Path(os.getenv("NUCLEI_TEMPLATES_DIR", str(_DEFAULT_NUCLEI_DIR)))
PROFILES_DIR = CURATED_TEMPLATES_DIR / "profiles"

NUCLEI_BIN = shutil.which("nuclei") or "/usr/local/bin/nuclei"

def resolve_profile_file(scan_profile: str) -> Path:
    """
    Memastikan file profile Nuclei mengarah ke direktori template yang valid.
    Jika template path di profile adalah relative path atau tidak cocok dengan
    lokasi filesystem saat ini, buat profile runtime otomatis dengan absolute
    path yang disesuaikan.
    """
    prof_name = "full" if str(scan_profile).lower() in ["full", "deep"] else "quick"
    base_file = PROFILES_DIR / f"secaudit-{prof_name}.yml"
    if not base_file.exists():
        base_file = PROFILES_DIR / "secaudit-quick.yml"

    try:
        if base_file.exists():
            with open(base_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            templates = data.get("templates", [])

            new_templates = []
            needs_rewrite = False
            for t in templates:
                p = Path(t)
                if p.is_absolute() and p.exists():
                    new_templates.append(str(p))
                elif (CURATED_TEMPLATES_DIR / t).exists():
                    new_templates.append(str((CURATED_TEMPLATES_DIR / t).resolve()))
                    needs_rewrite = True
                else:
                    resolved = None
                    for marker in ["nuclei", "curated-templates"]:
                        if marker in p.parts:
                            idx = p.parts.index(marker)
                            rel_sub = Path(*p.parts[idx + 1:])
                            cand = CURATED_TEMPLATES_DIR / rel_sub
                            if cand.exists():
                                resolved = cand
                                break
                    if resolved:
                        new_templates.append(str(resolved.resolve()))
                        needs_rewrite = True
                    else:
                        new_templates.append(t)

            if needs_rewrite:
                data["templates"] = new_templates
                runtime_prof = PROFILES_DIR / f".runtime-{prof_name}.yml"
                with open(runtime_prof, "w", encoding="utf-8") as rf:
                    yaml.dump(data, rf)
                return runtime_prof
    except Exception as e:
        logger.warning(f"[Nuclei] Gagal mengevaluasi path profile: {e}")

    return base_file

# Pemetaan kategori Nuclei ke kategori standar SecAudit / OWASP
TAG_CATEGORY_MAP = {
    "exposure": "SENSITIVE_DATA_EXPOSURE",
    "config": "SECURITY_MISCONFIGURATION",
    "env": "CREDENTIAL_LEAK",
    "git": "SENSITIVE_DATA_EXPOSURE",
    "backup": "BACKUP_FILE_DISCLOSURE",
    "misconfig": "SECURITY_MISCONFIGURATION",
    "cors": "CORS_MISCONFIGURATION",
    "header": "SECURITY_HEADERS",
    "ssl": "INSECURE_COMMUNICATION",
    "tls": "INSECURE_COMMUNICATION",
    "takeover": "SUBDOMAIN_TAKEOVER",
    "actuator": "EXPOSED_ADMIN_PANEL",
    "panel": "EXPOSED_ADMIN_PANEL",
    "graphql": "API_EXPOSURE",
    "sqli": "INJECTION_SQLI",
    "xss": "INJECTION_XSS",
    "lfi": "INJECTION_LFI",
    "ssrf": "SERVER_SIDE_REQUEST_FORGERY",
    "rce": "REMOTE_CODE_EXECUTION",
    "cve": "KNOWN_VULNERABILITY",
}

def map_nuclei_severity(raw_sev: str) -> str:
    s = str(raw_sev).strip().upper()
    if s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        return s
    return "MEDIUM"

def determine_category(tags: List[str], template_id: str) -> str:
    lower_id = template_id.lower()
    for tag in tags:
        t = tag.lower()
        if t in TAG_CATEGORY_MAP:
            return TAG_CATEGORY_MAP[t]
    for key, cat in TAG_CATEGORY_MAP.items():
        if key in lower_id:
            return cat
    return "VULNERABILITY"

async def run_nuclei_scan(
    target_url: str,
    scan_profile: str = "quick",  # "quick" or "full"
    concurrency: int = 25,
    rate_limit: int = 50,
    timeout_seconds: int = 180,
    progress_callback: Optional[Callable[[str, int, str], Awaitable[None]]] = None
) -> List[Dict[str, Any]]:
    """
    Menjalankan audit Nuclei berbasis profile terkurasi SecAudit.
    Mengembalikan findings list dalam format standar SecAudit.
    """
    if not os.path.exists(NUCLEI_BIN):
        logger.warning(f"[Nuclei] Binary nuclei tidak ditemukan di {NUCLEI_BIN}. Scanning Nuclei dilewati.")
        return []

    profile_file = resolve_profile_file(scan_profile)

    cmd = [
        NUCLEI_BIN,
        "-target", target_url,
        "-profile", str(profile_file),
        "-silent",
        "-jsonl",
        "-no-mhe",
        "-stats=false",
        "-c", str(concurrency),
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "1"
    ]

    findings: List[Dict[str, Any]] = []

    try:
        prof_display = "Comprehensive (114 templates)" if "full" in profile_file.name.lower() else "Quick (25 templates)"
        logger.info(f"[Nuclei] Memulai scanning {target_url} dengan profile {profile_file.name}")
        if progress_callback:
            await progress_callback(
                "NUCLEI:EXEC",
                50,
                f"Menjalankan Nuclei DAST & Vulnerability Scanner ({prof_display})..."
            )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning(f"[Nuclei] Scan timeout ({timeout_seconds}s) untuk {target_url}")
            return findings

        if stderr:
            stderr_txt = stderr.decode("utf-8", errors="ignore").strip()
            if stderr_txt:
                logger.debug(f"[Nuclei stderr] {stderr_txt[:200]}")

        for line in stdout.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                template_id = data.get("template-id", "unknown-nuclei-rule")
                info = data.get("info", {})
                severity = map_nuclei_severity(info.get("severity", "MEDIUM"))
                tags = info.get("tags", [])
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]

                category = determine_category(tags, template_id)
                classification = info.get("classification", {}) or {}

                cwe_list = classification.get("cwe-id", [])
                cwe_id = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "CWE-200"

                cvss_score = classification.get("cvss-score")
                if cvss_score is None:
                    # Berikan default score berdasarkan severity
                    score_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}
                    cvss_score = score_map.get(severity, 5.0)
                else:
                    try:
                        cvss_score = float(cvss_score)
                    except:
                        cvss_score = 5.0

                matched_url = data.get("matched-at", target_url)
                curl_cmd = data.get("curl-command", "")
                matcher_name = data.get("matcher-name", "")
                extracted = data.get("extracted-results", [])

                finding = {
                    "id": f"bb-nuclei-{template_id}-{uuid.uuid4().hex[:6]}",
                    "rule_id": f"nuclei-{template_id}",
                    "category": category,
                    "severity": severity,
                    "title": info.get("name", template_id),
                    "description": info.get("description", f"Nuclei matcher {template_id} terpicu pada {matched_url}"),
                    "cwe_id": cwe_id,
                    "owasp_category": "A05:2021-Security Misconfiguration" if "MISCONFIG" in category else "A01:2021-Broken Access Control",
                    "cvss_score": cvss_score,
                    "location": {
                        "source_origin": "NUCLEI_ENGINE",
                        "path": matched_url,
                        "line_start": 1,
                        "line_end": 1
                    },
                    "redacted_code_snippet": curl_cmd if curl_cmd else f"Detected at: {matched_url}",
                    "evidence_metadata": {
                        "template_id": template_id,
                        "matcher_name": matcher_name,
                        "extracted_results": extracted,
                        "reference": info.get("reference", []),
                        "curl_command": curl_cmd,
                        "tags": tags
                    }
                }
                findings.append(finding)
            except Exception as parse_err:
                logger.error(f"[Nuclei] Gagal parsing output line: {parse_err}")

        logger.info(f"[Nuclei] Scan selesai untuk {target_url}. Ditemukan {len(findings)} temuan.")
        if progress_callback:
            await progress_callback(
                "NUCLEI:DONE",
                55,
                f"Nuclei scanner selesai: {len(findings)} temuan kerentanan berhasil diverifikasi."
            )

    except Exception as e:
        logger.error(f"[Nuclei] Exception saat menjalankan scan: {e}")

    return findings
