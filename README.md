# AuraSec (GeistSecurity)

> Autonomous Whitebox & Blackbox Web Security Audit Platform powered by continuous verification.

[![TestSprite Hackathon Season 4](https://img.shields.io/badge/TestSprite-Hackathon%20S4-blueviolet?style=flat-square)](https://www.testsprite.com/hackathon-s4)
[![Backend Tests](https://img.shields.io/badge/Pytest-27%2F27%20Passed-brightgreen?style=flat-square)](backend/tests/)
[![Frontend Lint](https://img.shields.io/badge/Oxlint-Passing-success?style=flat-square)](frontend/)
[![Design System](https://img.shields.io/badge/Design-Geist%20Dark-black?style=flat-square)](https://vercel.com)

---

## Live Application & Submission Info

- **Live URL**: `https://geist-security.vercel.app` *(or custom domain configured on Vercel)*
- **GitHub Repository**: [https://github.com/AdliXSec/GeistSecurity](https://github.com/AdliXSec/GeistSecurity)
- **Submitter / Team**: Deadlee (`deadlee.__82022`)
- **Event**: TestSprite Hackathon Season 4 (Oct 16 – Oct 22, 2026)

---

## Overview

**AuraSec (GeistSecurity)** is a web security auditing and posture evaluation platform built to bridge the gap between static code analysis (SAST) and dynamic runtime scanning (DAST). 

Engineered with a minimalist Geist dark aesthetic and an autonomous multi-phase audit engine, AuraSec inspects public client bundles, HTTP configurations, source repositories, and server endpoints to deliver actionable, reproducible proof-of-concept (PoC) security reports.

### Key Capabilities

1. **Autonomous 6-Phase Audit Lifecycle**:
   - **Phase 1: Target Ingestion & Reconnaissance** — DNS resolution, TLS inspection, technologies fingerprinting.
   - **Phase 2: Asset & Endpoint Discovery** — Route crawling, Next.js chunk discovery, public script harvesting.
   - **Phase 3: Whitebox / Bundle AST Analysis** — Regex heuristics, Shannon entropy scanning for exposed keys, and AST sink analysis.
   - **Phase 4: DAST & Misconfiguration Audit** — Passive security header evaluation, cookie flag auditing, and CSP weakness checks.
   - **Phase 5: Threat Intelligence & CVE Correlation** — Automated matching against known vulnerabilities (`CVE-2021-23017`, `CVE-2024-29041`, `CVE-2021-44228`).
   - **Phase 6: Compliance Aggregation & Grading** — Real-time posture scoring, CVSS v3.1 calculation, and executive remediation export.

2. **Real-time SSE Streaming with Fail-Safe Ticker**:
   - Persistent Server-Sent Events (SSE) telemetry pipeline with instantaneous status synchronization.
   - Resilient pause/resume controls that guarantee audit progression from 0% to 100% without client-side stalls.

3. **Geist Dark UI Architecture**:
   - Strict monochrome palette (`#000000`, `#0a0a0a`, `#111113`, `#1e1e22`, `#27272a`) with zero Unicode emoji slop.
   - Interactive severity tabs (`All`, `Critical`, `High`, `Medium`, `Low`), CVE filter chips, and instant full-text vulnerability search.

---

## What the Test Suite Covers

Our verification strategy combines local automated test suites with cloud-based autonomous verification powered by **TestSprite 3.0 Web Portal + GitHub App Integration**:

### 1. Security Scanner & Rule Assertions (`backend/tests/`)
- **Cookie Security Flags (`CWE-614`, `CWE-1004`)**:
  - Validates detection of cookies lacking `Secure`, `HttpOnly`, or proper `SameSite` flags.
- **Passive HTTP Security Headers (`CWE-1021`, `CWE-319`, `CWE-79`)**:
  - Asserts detection of missing `Strict-Transport-Security` (HSTS).
  - Asserts detection of missing `X-Content-Type-Options: nosniff`.
  - Asserts detection of missing `X-Frame-Options` and clickjacking vectors.
  - Asserts verification of `Referrer-Policy` and `Permissions-Policy`.
- **Content Security Policy (CSP) Directives (`CWE-1021`)**:
  - Checks for missing or overly permissive script sources and unsafe inline execution directives.
- **Vulnerable Component & CVE Matching (`CWE-1395`, `CWE-79`)**:
  - Accurate identification and badge generation for specific CVEs (`CVE-2021-23017`, `CVE-2015-9251`, `CVE-2024-29041`).
- **DOM XSS & Unsafe Sink Taint Flows (`CWE-79`)**:
  - Detects client-side bundle patterns where URL parameters (`window.location.search`) directly sink into dangerous sinks like `element.innerHTML`.
- **Entropy & Secret Scanning**:
  - Shannon entropy verification to flag hardcoded API tokens (`sk-proj-...`) with automatic masking and redaction.

### 2. Autonomous TestSprite Verification (Web Portal & GitHub App)
- **Continuous PR Checks**: Every pull request triggers an automated TestSprite test run against the live app endpoint.
- **End-to-End User Journeys**:
  - Audit creation via Launchpad (URL, GitHub repo target, mode selection).
  - Progress tracking through all 6 phases up to 100% completion.
  - Interactive report inspection, CVE chip filtering, and search queries (e.g. searching for `"cookie"`, `"security header"`, `"Content Security Policy"`).
  - Dashboard state persistence with zero-state protection (`DEFAULT_PROJECTS` fallback preventing empty repository blockers).

### 3. Local Verification Results
```bash
# Backend Test Suite (Pytest)
collected 27 items
backend/tests/test_auth.py .                                             [  3%]
backend/tests/test_database.py ..                                        [ 11%]
backend/tests/test_nuclei.py ......                                      [ 33%]
backend/tests/test_recon.py .......                                      [ 59%]
backend/tests/test_rules.py ....                                         [ 74%]
backend/tests/test_user_isolation.py .                                   [ 77%]
backend/tests/test_whitebox.py ......                                    [100%]
============================== 27 passed in 4.28s ==============================

# Frontend Lint (Oxlint)
> oxlint
No syntax, type, or lint errors.

# Frontend Production Build
> tsc -b && vite build
✓ 1953 modules transformed.
dist/index.html                   0.90 kB
dist/assets/index-CEmHRszc.css   36.08 kB
dist/assets/index-BTv_So2M.js   525.42 kB
✓ built in 1.85s
```

---

## Project Structure

```
├── backend/
│   ├── main.py                  # FastAPI application entrypoint & routing
│   ├── config.py                # Environment & SQLite path configuration
│   ├── database.py              # Aiosqlite database initialization & schema
│   ├── routers/
│   │   ├── audits.py            # Audit lifecycle, SSE stream & report endpoints
│   │   ├── auth.py              # JWT authentication & session isolation
│   │   └── projects.py          # Monitored projects & health score API
│   ├── services/
│   │   ├── audit_orchestrator.py# 6-phase pipeline coordinator
│   │   ├── recon_engine.py      # Network, DNS, and HTTP security header probe
│   │   ├── blackbox_scanner.py  # DAST active & passive scanner
│   │   └── whitebox_scanner.py  # Client JS AST parser & secret entropy engine
│   └── tests/                   # Pytest automated test suites (27 tests)
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── HomePage.tsx     # Hero landing page & quick scan launcher
│   │   │   ├── DashboardPage.tsx# Monitored repositories & severity filters
│   │   │   ├── NewAuditPage.tsx # Audit configuration launchpad
│   │   │   ├── ProgressPage.tsx # Real-time 6-phase progress & SSE logs
│   │   │   └── ReportPage.tsx   # Detailed findings, CVE badges & remediation
│   │   └── lib/
│   │       └── api.ts           # Centralized API client & state utilities
│   ├── package.json
│   └── vite.config.ts
├── vercel.json                  # Multi-service Vercel deployment configuration
└── README.md
```

---

## Local Development Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm

### 1. Clone the Repository
```bash
git clone https://github.com/AdliXSec/GeistSecurity.git
cd GeistSecurity
```

### 2. Backend Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Frontend Setup
```bash
npm install
npm run dev
```
The application will be available at `http://localhost:5173`.

---

## TestSprite GitHub Integration Workflow

1. **Portal Test Suite**: Test suites are generated in the TestSprite 3.0 Web Portal targeting the live public URL.
2. **GitHub App Installation**: TestSprite GitHub App is installed on `AdliXSec/GeistSecurity` with access to pull requests.
3. **Continuous PR Feedback**: Every pull request automatically triggers the TestSprite runner:
   - Evaluates UI routes and backend API endpoints.
   - Comments with detailed pass/fail breakdowns.
   - Prevents regressions before merging to `main`.

---

## License

This project is licensed under the MIT License. Developed for the TestSprite Hackathon Season 4.
