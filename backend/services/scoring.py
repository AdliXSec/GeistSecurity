from typing import List, Dict, Any, Tuple

def calculate_posture_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Menghitung security posture score berdasarkan temuan kerentanan sesuai PRD:
    Score = max(0, 100 - (25 * Nc + 15 * Nh + 7 * Nm + 3 * Nl))
    Aturan Kunci: Jika Nc >= 1, grade dibatasi maksimal Grade D!
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1

    deductions = (
        counts["critical"] * 25 +
        counts["high"] * 15 +
        counts["medium"] * 7 +
        counts["low"] * 3
    )

    raw_score = max(0, 100 - deductions)

    # Menentukan Grade
    if raw_score >= 90:
        grade = "A"
        grade_label = "Optimal Security Posture — Enterprise Hardened"
    elif raw_score >= 80:
        grade = "B"
        grade_label = "Moderate Security — Minor Hardening Recommended"
    elif raw_score >= 65:
        grade = "C"
        grade_label = "Elevated Risk — Action Required Before Production"
    elif raw_score >= 50:
        grade = "D"
        grade_label = "High Risk — Immediate Remediation Required"
    else:
        grade = "F"
        grade_label = "Critical Exposure — Block Deployment Immediately"

    # ATURAN KUNCI: Jika terdapat minimal 1 Critical, Grade maksimal adalah D!
    if counts["critical"] >= 1 and grade in ("A", "B", "C"):
        grade = "D"
        grade_label = "High Risk — Locked to Grade D due to Critical Vulnerability"

    return {
        "score": raw_score,
        "max_score": 100,
        "grade": grade,
        "grade_label": grade_label,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "summary_counts": counts
    }
