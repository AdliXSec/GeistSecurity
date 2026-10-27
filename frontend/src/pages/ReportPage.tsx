import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Lock,
  Radio,
  Layers,
  FolderSearch,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  Boxes,
  Braces,
  ExternalLink,
  GitBranch,
  Cpu,
  Code2,
  Bug,
} from 'lucide-react';
import { getAuditReport, type AuditReport, type ReconSummary } from '../lib/api';

const DEFAULT_RECON_SUMMARY: ReconSummary = {
  open_ports: [
    { port: 80, service: 'HTTP (Web)', status: 'OPEN', risk: 'INFO' },
    { port: 443, service: 'HTTPS (TLS)', status: 'OPEN', risk: 'INFO' },
    { port: 3306, service: 'MySQL Database', status: 'OPEN', risk: 'CRITICAL' },
    { port: 8080, service: 'Alt HTTP / Dev', status: 'OPEN', risk: 'MEDIUM' },
  ],
  ssl_summary: {
    valid: true,
    days_left: 84,
    issuer: "Let's Encrypt Authority X3",
    protocol: 'TLSv1.3',
    redirect_https: true,
    expired: false,
  },
  detected_tech: [
    { name: 'Next.js', version: '14.1.0', outdated: false, cve_count: 0, cves: [] },
    { name: 'Nginx', version: '1.18.0', outdated: true, cve_count: 1, cves: ['CVE-2021-23017'] },
    { name: 'jQuery', version: '2.1.4', outdated: true, cve_count: 2, cves: ['CVE-2015-9251', 'CVE-2019-11358'] },
  ],
  sensitive_dirs: [
    {
      path: '/.env',
      status: 200,
      risk: 'CRITICAL',
      detail: 'Environment configuration file (.env) publicly accessible, leaking production database credentials.',
    },
    {
      path: '/robots.txt',
      status: 200,
      risk: 'INFO',
      detail: 'Robots.txt file exposes internal administrative and staging paths.',
      disallowed_routes: ['/admin', '/internal-api', '/staging'],
    },
    {
      path: '/swagger.json',
      status: 200,
      risk: 'MEDIUM',
      detail: 'Internal Swagger/OpenAPI endpoint specification publicly accessible.',
    },
  ],
  html_leaks: [
    { type: 'COMMENT', snippet: '<!-- TODO: remove staging API key before production deployment -->', line: 42, entropy: 3.2 },
    { type: 'EMAIL', snippet: 'dev-lead***@startupkamu.id', line: 58, entropy: 3.1 },
  ],
  js_assets: [
    {
      url: 'https://demo-fintech.auraglass.io/_next/static/chunks/main-app-8f2a.js',
      filename: 'main-app-8f2a.js',
      size_kb: 142.6,
      discovered_endpoints: ['/api/v1/auth/session', '/api/v1/payments/process', '/api/internal/telemetry'],
      secrets_found: 1,
      sourcemap_exposed: false,
      sourcemap_url: null,
      sub_chunks: ['chunk-auth-9b1c.js', 'chunk-dashboard-7e4a.js'],
    },
    {
      url: 'https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js',
      filename: 'chunk-auth-9b1c.js',
      size_kb: 64.2,
      discovered_endpoints: ['/api/v1/auth/login', '/api/v1/users/me'],
      secrets_found: 0,
      sourcemap_exposed: true,
      sourcemap_url: 'https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js.map',
      sub_chunks: [],
    },
  ],
};

const FALLBACK_REPORT: AuditReport = {
  session_id: 'demo-fintech',
  project_name: 'Fintech Payment Gateway Demo',
  mode: 'HYBRID',
  status: 'COMPLETED',
  audited_at: new Date().toISOString(),
  duration_ms: 18450,
  target_info: {
    target_url: 'https://demo-fintech.auraglass.io',
    github_repo_url: 'https://github.com/auraglass/fintech-dashboard-api',
    branch: 'main',
    detected_tech_stack: ['FastAPI', 'React 18', 'Vite', 'TailwindCSS', 'OSV.dev', 'Tree-sitter'],
  },
  posture_score: {
    score: 42,
    max_score: 100,
    grade: 'D',
    grade_label: 'Poor - Critical Vulnerabilities Blocked',
    summary_counts: {
      critical: 2,
      high: 1,
      medium: 2,
      low: 1,
      info: 1,
    },
  },
  recon_summary: DEFAULT_RECON_SUMMARY,
  findings: [
    {
      id: 'f-recon-port-3306',
      rule_id: 'PORT-EXPOSED-MYSQL',
      category: 'PORT_SCAN',
      severity: 'CRITICAL',
      title: 'Critical Database Port Exposed Publicly (MySQL Database - Port 3306)',
      cwe_id: 'CWE-284',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 9.1,
      location: {
        source_origin: 'NETWORK_PORT_SCANNER',
        path: 'tcp://demo-fintech.auraglass.io:3306',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'TCP Port 3306/open (MySQL Database)\nStatus: EXPOSED TO INTERNET\nService: MySQL 8.0 Protocol',
      evidence_metadata: {
        host: 'demo-fintech.auraglass.io',
        port: 3306,
        service: 'MySQL Database',
        risk_level: 'CRITICAL',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'MySQL database port (3306) is directly exposed to the public internet without firewall or VPN encapsulation, leaving the database vulnerable to brute-force credential stuffing and remote exploitation.',
        remediation_steps: [
          'Block port 3306 on the public interface using host firewalls (iptables/nftables) or cloud security groups.',
          'Configure bind-address = 127.0.0.1 in MySQL server configuration (/etc/mysql/my.cnf).',
          'Enforce internal-only access via SSH tunnels, VPC peering, or dedicated wireguard bastion hosts.',
        ],
        code_patch: {
          language: 'ini',
          original_code: '# /etc/mysql/mysql.conf.d/mysqld.cnf\nbind-address = 0.0.0.0',
          patched_code: '# /etc/mysql/mysql.conf.d/mysqld.cnf\nbind-address = 127.0.0.1',
        },
      },
    },
    {
      id: 'f-recon-env-leak',
      rule_id: 'SENSITIVE-PATH-ENV',
      category: 'DIR_FINDER',
      severity: 'CRITICAL',
      title: 'Sensitive Configuration Environment File Publicly Exposed (/.env)',
      cwe_id: 'CWE-552',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 9.3,
      location: {
        source_origin: 'CURATED_DIR_FINDER',
        path: 'https://demo-fintech.auraglass.io/.env',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'DB_HOST=10.0.1.5\nDB_USER=fintech_app\nDB_PASS=********************\nJWT_SECRET=********************',
      evidence_metadata: {
        path: '/.env',
        status_code: 200,
        leaked_keys: ['DB_USER', 'DB_PASS', 'JWT_SECRET'],
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'The .env configuration file is directly exposed to public HTTP requests due to missing dotfile denial rules in the reverse proxy, leaking production database credentials and signing secrets.',
        remediation_steps: [
          'Add explicit denial rules for dotfiles (.*) in reverse proxy configurations (Nginx/Apache/Caddy).',
          'Ensure the .env file is situated outside the web server document root directory.',
          'Immediately rotate all secrets, database credentials, and signing keys exposed in the leaked file.',
        ],
        code_patch: {
          language: 'nginx',
          original_code: '# nginx.conf\nlocation / {\n    try_files $uri $uri/ =404;\n}',
          patched_code: '# nginx.conf\nlocation ~ /\\.(env|git|htaccess) {\n    deny all;\n    return 404;\n}',
        },
      },
    },
    {
      id: 'f-recon-nginx-cve',
      rule_id: 'OUTDATED-PKG-CVE-2021-23017',
      category: 'TECH_AND_CVE',
      severity: 'HIGH',
      title: 'Web Server Component Vulnerable to CVE-2021-23017 (Nginx 1.18.0)',
      cwe_id: 'CWE-119',
      owasp_category: 'A06:2021-Vulnerable and Outdated Components',
      cvss_score: 8.1,
      location: {
        source_origin: 'TECH_FINGERPRINT',
        path: 'Server: nginx/1.18.0',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nX-Powered-By: Next.js',
      evidence_metadata: {
        component: 'Nginx',
        version: '1.18.0',
        cve: 'CVE-2021-23017',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Nginx version 1.18.0 suffers from a 1-byte memory overwrite flaw in the DNS resolver module (CVE-2021-23017), which could allow remote unauthenticated attackers to cause a denial of service or execute arbitrary code.',
        remediation_steps: [
          'Upgrade Nginx package to the latest stable release (minimum 1.20.1 or 1.24+).',
          'Conceal server banner version headers using server_tokens off; directive.',
        ],
        code_patch: {
          language: 'nginx',
          original_code: '# nginx.conf\nhttp {\n    # server_tokens default on\n}',
          patched_code: '# nginx.conf\nhttp {\n    server_tokens off;\n}',
        },
      },
    },
    {
      id: 'f-recon-jquery-cve',
      rule_id: 'OUTDATED-PKG-CVE-2015-9251',
      category: 'TECH_AND_CVE',
      severity: 'MEDIUM',
      title: 'Client Library Component Vulnerable to CVE-2015-9251 (jQuery 2.1.4)',
      cwe_id: 'CWE-79',
      owasp_category: 'A06:2021-Vulnerable and Outdated Components',
      cvss_score: 6.1,
      location: {
        source_origin: 'TECH_FINGERPRINT',
        path: 'https://demo-fintech.auraglass.io/assets/jquery-2.1.4.min.js',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: '/*! jQuery v2.1.4 | (c) 2005, 2015 jQuery Foundation, Inc. | jquery.org/license */',
      evidence_metadata: {
        component: 'jQuery',
        version: '2.1.4',
        cve: 'CVE-2015-9251',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'jQuery before 3.0.0 is vulnerable to Cross-Site Scripting (CVE-2015-9251) via parseHTML which does not strip malicious executable scripts when parsing untrusted markup.',
        remediation_steps: [
          'Upgrade jQuery to version 3.5.0 or later (recommended 3.7.1).',
          'Use modern native DOM APIs (fetch, querySelector) to reduce dependency on legacy client libraries.',
        ],
        code_patch: {
          language: 'html',
          original_code: '<script src="/assets/jquery-2.1.4.min.js"></script>',
          patched_code: '<script src="/assets/jquery-3.7.1.min.js"></script>',
        },
      },
    },
    {
      id: 'f-recon-cookie-flags',
      rule_id: 'COOKIE-PROTECTION-FLAGS-MISSING',
      category: 'MISCONFIG_DEFAULT',
      severity: 'MEDIUM',
      title: 'Missing Cookie Protection Flags (Secure, HttpOnly, SameSite)',
      cwe_id: 'CWE-614',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 5.4,
      location: {
        source_origin: 'DAST_HEADER_SCANNER',
        path: 'Set-Cookie: session_id=a8f9c21b4e; Path=/;',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'Set-Cookie: session_id=a8f9c21b4e; Path=/; Domain=demo-fintech.auraglass.io\n// Warning: Missing Secure, HttpOnly, and SameSite cookie protection flags',
      evidence_metadata: {
        cookie_name: 'session_id',
        missing_flags: ['Secure', 'HttpOnly', 'SameSite'],
        issue: 'Missing cookie protection flags enable session hijacking and CSRF vectors',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Session and authentication cookies transmitted without Secure, HttpOnly, and SameSite attributes can be intercepted over unencrypted channels or accessed via client-side cross-site scripting (XSS).',
        remediation_steps: [
          'Enforce HttpOnly flag on all session cookies to prevent access via document.cookie.',
          'Set Secure flag so cookies are only transmitted over HTTPS connections.',
          'Configure SameSite=Lax or SameSite=Strict to mitigate Cross-Site Request Forgery (CSRF).',
        ],
        code_patch: {
          language: 'typescript',
          original_code: "res.setHeader('Set-Cookie', 'session_id=' + token + '; Path=/');",
          patched_code: "res.setHeader('Set-Cookie', 'session_id=' + token + '; Path=/; Secure; HttpOnly; SameSite=Lax');",
        },
      },
    },
    {
      id: 'f-recon-security-headers',
      rule_id: 'HTTP-SECURITY-HEADER-MISSING',
      category: 'MISCONFIG_DEFAULT',
      severity: 'MEDIUM',
      title: 'Missing Passive HTTP Security Headers (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options)',
      cwe_id: 'CWE-693',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 5.8,
      location: {
        source_origin: 'DAST_HEADER_SCANNER',
        path: 'HTTP Response Headers: https://demo-fintech.auraglass.io',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'HTTP/1.1 200 OK\n// Missing passive HTTP security headers:\n// - Strict-Transport-Security (HSTS): MISSING\n// - X-Frame-Options: MISSING\n// - X-Content-Type-Options: MISSING\n// - Referrer-Policy: MISSING',
      evidence_metadata: {
        missing_headers: ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'],
        issue: 'Missing passive HTTP security headers weaken defense against clickjacking and MIME sniffing',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Missing defensive HTTP security headers expose web applications to clickjacking framing attacks, MIME-type sniffing, and SSL stripping vectors.',
        remediation_steps: [
          'Implement Strict-Transport-Security with max-age=31536000 and includeSubDomains.',
          'Set X-Frame-Options to DENY or SAMEORIGIN to prevent framing clickjacking.',
          'Set X-Content-Type-Options to nosniff to enforce MIME-type compliance.',
        ],
        code_patch: {
          language: 'nginx',
          original_code: '# nginx.conf\nserver {\n    listen 443 ssl;\n}',
          patched_code: '# nginx.conf\nserver {\n    listen 443 ssl;\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n    add_header X-Frame-Options "SAMEORIGIN" always;\n    add_header X-Content-Type-Options "nosniff" always;\n    add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n}',
        },
      },
    },
    {
      id: 'f-recon-csp-weakness',
      rule_id: 'HTTP-MISSING-CSP',
      category: 'MISCONFIG_DEFAULT',
      severity: 'HIGH',
      title: 'Content Security Policy (CSP) Directives Missing & Unrestricted Script Execution',
      cwe_id: 'CWE-1021',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 7.2,
      location: {
        source_origin: 'DAST_HEADER_SCANNER',
        path: 'Content-Security-Policy: [HEADER NOT DETECTED]',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'HTTP/1.1 200 OK\nContent-Security-Policy: [HEADER NOT DETECTED]\n// Unrestricted script execution permitted without Content Security Policy protection',
      evidence_metadata: {
        header: 'Content-Security-Policy',
        issue: 'Content Security Policy weakness allows unconstrained script injection and cross-site framing',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Absence of Content Security Policy (CSP) headers allows arbitrary third-party scripts, inline event handlers, and data URIs to execute in victim browsers.',
        remediation_steps: [
          "Define a restrictive Content-Security-Policy header with default-src 'self'.",
          'Disallow unsafe-inline and unsafe-eval script sources.',
          'Restrict connect-src to authorized API gateways only.',
        ],
        code_patch: {
          language: 'nginx',
          original_code: '# Missing Content-Security-Policy\nadd_header X-Frame-Options "SAMEORIGIN";',
          patched_code: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';\" always;",
        },
      },
    },
    {
      id: 'f-public-bundle-sink',
      rule_id: 'PUBLIC-BUNDLE-UNSAFE-SINK-USAGE',
      category: 'DOM_XSS',
      severity: 'HIGH',
      title: 'Public Client Bundle Inspection: URL-Derived Input Connected to Unsafe DOM Sink (innerHTML)',
      cwe_id: 'CWE-79',
      owasp_category: 'A03:2021-Injection',
      cvss_score: 8.2,
      location: {
        source_origin: 'CLIENT_JS_BUNDLE_INSPECTION',
        path: '/_next/static/chunks/main-app-8f2a.js',
        line_start: 142,
        line_end: 145,
      },
      redacted_code_snippet: 'const query = new URLSearchParams(window.location.search).get("q");\nelement.innerHTML = "<div>Search result: " + query + "</div>";',
      evidence_metadata: {
        source: 'window.location.search',
        sink: 'element.innerHTML',
        taint_flow: 'URL-derived query parameter flows into innerHTML sink without sanitization',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Client-side JavaScript extracts URL parameters from window.location.search and concatenates them directly into element.innerHTML, exposing users to client-side DOM XSS attacks.',
        remediation_steps: [
          'Use element.textContent instead of element.innerHTML when rendering user-supplied strings.',
          'Sanitize markup with DOMPurify if HTML rendering is required.',
        ],
        code_patch: {
          language: 'javascript',
          original_code: 'element.innerHTML = "<div>Search result: " + query + "</div>";',
          patched_code: 'element.textContent = "Search result: " + (query || "");',
        },
      },
    },
    {
      id: 'f-recon-html-comment',
      rule_id: 'HTML-SENSITIVE-COMMENT-LEAK',
      category: 'HTML_METADATA',
      severity: 'MEDIUM',
      title: 'Sensitive Developer Comments Leaked in Production HTML (TODO / staging / api)',
      cwe_id: 'CWE-615',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 5.3,
      location: {
        source_origin: 'HTML_INSPECTOR',
        path: 'https://demo-fintech.auraglass.io (HTML Source)',
        line_start: 42,
        line_end: 42,
      },
      redacted_code_snippet: '<!-- TODO: remove staging API key before production deployment -->',
      evidence_metadata: {
        matched_keywords: ['TODO', 'staging', 'api', 'key'],
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Internal developer comments left inside production HTML files expose architectural cues and internal staging credentials to malicious actors.',
        remediation_steps: [
          'Configure the production bundler HTML minifier to strip all comments automatically during build.',
          'Adopt pre-commit hygiene linters to block commits containing sensitive TODO/FIXME annotations.',
        ],
        code_patch: {
          language: 'html',
          original_code: '<!-- TODO: remove staging API key before production deployment -->\n<div>Content</div>',
          patched_code: '<!-- Sensitive developer comments stripped in production build -->\n<div>Content</div>',
        },
      },
    },
    {
      id: 'f-recon-js-smap',
      rule_id: 'JS-SOURCE-MAP-EXPOSED',
      category: 'JS_CRAWLER_SECRET',
      severity: 'MEDIUM',
      title: 'Client JavaScript Source Map (.map) Exposed Publicly (chunk-auth-9b1c.js.map)',
      cwe_id: 'CWE-540',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 5.3,
      location: {
        source_origin: 'CLIENT_JS_CRAWLER',
        path: 'https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js.map',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: '//# sourceMappingURL=chunk-auth-9b1c.js.map\n// Original TypeScript source code accessible: auth.ts, session.ts, tokens.ts',
      evidence_metadata: {
        source_map_url: 'https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js.map',
        parent_js: 'https://demo-fintech.auraglass.io/_next/static/chunks/chunk-auth-9b1c.js',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'Unminified source map files (.map) uploaded to public production servers allow anyone to reconstruct full TypeScript source code, business logic, and internal comments.',
        remediation_steps: [
          'Disable public sourcemap emission in build configuration (e.g. productionBrowserSourceMaps: false in next.config.js).',
          'Configure web server to deny requests for *.map files.',
        ],
        code_patch: {
          language: 'javascript',
          original_code: '// next.config.js\nmodule.exports = {\n  productionBrowserSourceMaps: true,\n};',
          patched_code: '// next.config.js\nmodule.exports = {\n  productionBrowserSourceMaps: false,\n};',
        },
      },
    },
    {
      id: 'finding-sec-1',
      rule_id: 'SEC-ENTROPY-001',
      category: 'SECRET_LEAK',
      severity: 'CRITICAL',
      title: 'OpenAI API Secret Key Leaked in Static JavaScript Bundle',
      cwe_id: 'CWE-798',
      owasp_category: 'A07:2021-Identification and Authentication Failures',
      cvss_score: 9.3,
      location: {
        source_origin: 'WHITEBOX_SAST',
        path: 'src/services/aiService.ts',
        line_start: 14,
        line_end: 18,
      },
      redacted_code_snippet: '14 | export const openAiClient = {\n15 |   apiKey: "sk-pr...**", // [Zero Leak Redacted]\n16 |   model: "gpt-4-turbo"\n17 | };',
      evidence_metadata: {
        entropy_score: 4.88,
        threshold: 4.2,
        secret_type: 'OpenAI Project API Key',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'OpenAI API secret key is hardcoded directly into client-side JavaScript. Anyone inspecting client-side resources can extract and abuse these production credentials.',
        remediation_steps: [
          'Immediately revoke the exposed sk-proj-*** key from the OpenAI developer dashboard.',
          'Migrate all OpenAI completions to an authenticated backend proxy endpoint.',
          'Use environment variables (OPENAI_API_KEY) on the server side only.',
        ],
        code_patch: {
          language: 'typescript',
          original_code: '// Unsafe: Hardcoded client secret\nexport const getCompletion = async (prompt: string) => {\n  return fetch("https://api.openai.com/v1/chat/completions", {\n    headers: { Authorization: "Bearer «redacted:sk-…»" },\n    body: JSON.stringify({ prompt })\n  });\n};',
          patched_code: '// Safe: Server-side proxy call\nexport const getCompletion = async (prompt: string) => {\n  return fetch("/api/v1/ai/completion", {\n    method: "POST",\n    headers: { "Content-Type": "application/json" },\n    body: JSON.stringify({ prompt })\n  });\n};',
        },
      },
    },
    {
      id: 'finding-sec-2',
      rule_id: 'SEC-XSS-002',
      category: 'DOM_XSS',
      severity: 'HIGH',
      title: 'Reflected DOM Cross-Site Scripting (XSS) via dangerouslySetInnerHTML',
      cwe_id: 'CWE-79',
      owasp_category: 'A03:2021-Injection',
      cvss_score: 7.8,
      location: {
        source_origin: 'WHITEBOX_SAST',
        path: 'src/components/SearchModal.tsx',
        line_start: 42,
        line_end: 45,
      },
      redacted_code_snippet: '42 | const q = new URLSearchParams(window.location.search).get("q");\n43 | return <div dangerouslySetInnerHTML={{ __html: q || "" }} />;',
      evidence_metadata: {
        sink: 'dangerouslySetInnerHTML',
        source: 'window.location.search',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'URL query parameter "q" is injected directly into DOM via dangerouslySetInnerHTML without sanitization, allowing adversaries to execute arbitrary JavaScript payloads.',
        remediation_steps: [
          'Eliminate dangerouslySetInnerHTML usage.',
          'Render query values as standard JSX text nodes: {q}.',
          'If HTML rendering is necessary, sanitize with DOMPurify.',
        ],
        code_patch: {
          language: 'tsx',
          original_code: '// Unsafe innerHTML injection\n<div dangerouslySetInnerHTML={{ __html: q || "" }} />',
          patched_code: '// Safe JSX text node rendering\n<div className="search-highlight">{q || ""}</div>',
        },
      },
    },
    {
      id: 'finding-sec-3',
      rule_id: 'SEC-SCA-003',
      category: 'VULNERABLE_DEPENDENCY',
      severity: 'MEDIUM',
      title: 'OSV.dev CVE-2021-23337: Prototype Pollution in lodash < 4.17.21',
      cwe_id: 'CWE-1321',
      owasp_category: 'A06:2021-Vulnerable and Outdated Components',
      cvss_score: 6.2,
      location: {
        source_origin: 'WHITEBOX_SAST',
        path: 'package-lock.json',
        line_start: 182,
        line_end: 186,
      },
      redacted_code_snippet: '"node_modules/lodash": {\n  "version": "4.17.20",\n  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"\n}',
      evidence_metadata: {
        package: 'lodash',
        vulnerable_range: '< 4.17.21',
        fixed_version: '4.17.21',
        cve: 'CVE-2021-23337',
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'The template function in lodash versions prior to 4.17.21 is vulnerable to Prototype Pollution when processing uncurated template options.',
        remediation_steps: [
          'Run "npm install lodash@^4.17.21" to upgrade the dependency.',
          'Execute "npm audit fix" to enforce safe dependency resolution.',
        ],
        code_patch: {
          language: 'json',
          original_code: '"dependencies": {\n  "lodash": "4.17.20"\n}',
          patched_code: '"dependencies": {\n  "lodash": "^4.17.21"\n}',
        },
      },
    },
    {
      id: 'finding-sec-4',
      rule_id: 'SEC-HDR-004',
      category: 'DAST_HEADER',
      severity: 'LOW',
      title: 'Missing Content-Security-Policy (CSP) & Strict-Transport-Security (HSTS)',
      cwe_id: 'CWE-693',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cvss_score: 3.8,
      location: {
        source_origin: 'BLACKBOX_DAST',
        path: 'HTTP Response Headers',
        line_start: 1,
        line_end: 1,
      },
      redacted_code_snippet: 'HTTP/1.1 200 OK\nServer: nginx/1.24\n// Content-Security-Policy: [MISSING]\n// Strict-Transport-Security: [MISSING]',
      evidence_metadata: {
        missing_headers: ['Content-Security-Policy', 'Strict-Transport-Security'],
      },
      ai_remediation: {
        model: 'gemini-2.5-flash',
        risk_explanation:
          'HTTP responses do not include CSP and HSTS headers, elevating susceptibility to man-in-the-middle attacks and unauthorized third-party script execution.',
        remediation_steps: [
          'Add security headers middleware in reverse proxy or web application.',
          'Configure Content-Security-Policy with default-src \'self\'.',
          'Enforce HSTS with max-age=31536000; includeSubDomains.',
        ],
        code_patch: {
          language: 'python',
          original_code: '@app.get("/")\nasync def root():\n    return {"status": "ok"}',
          patched_code: '@app.middleware("http")\nasync def add_security_headers(request, call_next):\n    response = await call_next(request)\n    response.headers["Content-Security-Policy"] = "default-src \'self\';"\n    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n    return response',
        },
      },
    },
  ],
};

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [report, setReport] = useState<AuditReport>(FALLBACK_REPORT);
  const [, setLoading] = useState(true);
  const [activeTabByFinding, setActiveTabByFinding] = useState<Record<string, 'summary' | 'evidence' | 'diff'>>({});
  const [copiedPatchId, setCopiedPatchId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Interactive Patch Simulation: Track which findings are simulated as patched
  const [patchedFindingIds, setPatchedFindingIds] = useState<Set<string>>(new Set());

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Fetch report from API
  useEffect(() => {
    const fetchReport = async () => {
      setLoading(true);
      try {
        const sessionId = id || 'demo-fintech';
        const data = await getAuditReport(sessionId);
        if (data && data.findings && data.posture_score) {
          if (!data.recon_summary && (id === 'demo-fintech' || !id)) {
            data.recon_summary = DEFAULT_RECON_SUMMARY;
          }
          setReport(data);
        } else {
          setReport(FALLBACK_REPORT);
        }
      } catch (err) {
        console.warn('Could not load backend report, using comprehensive fallback demo:', err);
        setReport(FALLBACK_REPORT);
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [id]);

  // Recalculate Posture Score & Grade based on Patched Findings (PRD Section 4.3 & 9.3)
  const activeFindings = report.findings.filter((f) => !patchedFindingIds.has(f.id));

  const countCrit = activeFindings.filter((f) => f.severity === 'CRITICAL').length;
  const countHigh = activeFindings.filter((f) => f.severity === 'HIGH').length;
  const countMed = activeFindings.filter((f) => f.severity === 'MEDIUM').length;
  const countLow = activeFindings.filter((f) => f.severity === 'LOW').length;

  // Formula PRD: Score = max(0, 100 - (25*Nc + 15*Nh + 7*Nm + 3*Nl))
  const rawScore = Math.max(0, 100 - (25 * countCrit + 15 * countHigh + 7 * countMed + 3 * countLow));

  // Hard Rule: if Nc >= 1, max grade is D
  let currentGrade = 'F';
  let gradeLabel = 'Critical Failure';
  let gradeColor = 'rose';

  if (rawScore >= 90) {
    currentGrade = 'A';
    gradeLabel = 'Excellent - Production Ready';
    gradeColor = 'emerald';
  } else if (rawScore >= 80) {
    currentGrade = 'B';
    gradeLabel = 'Good - Low Risk Profile';
    gradeColor = 'blue';
  } else if (rawScore >= 65) {
    currentGrade = 'C';
    gradeLabel = 'Fair - Remediation Recommended';
    gradeColor = 'amber';
  } else if (rawScore >= 50) {
    currentGrade = 'D';
    gradeLabel = 'Poor - Immediate Action Required';
    gradeColor = 'rose';
  } else {
    currentGrade = 'F';
    gradeLabel = 'Critical Risk';
    gradeColor = 'rose';
  }

  // Enforce Hard Rule
  if (countCrit >= 1 && ['A', 'B', 'C'].includes(currentGrade)) {
    currentGrade = 'D';
    gradeLabel = 'Capped at D (Critical Finding Detected)';
    gradeColor = 'rose';
  }

  const toggleSimulatePatch = (findingId: string) => {
    setPatchedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
        showToast('Patch simulasi dibatalkan.');
      } else {
        next.add(findingId);
        showToast('Patch simulasi diaplikasikan! Skor diperbarui.');
      }
      return next;
    });
  };

  const resetSimulation = () => {
    setPatchedFindingIds(new Set());
    showToast('Simulation reset.');
  };

  const copyCode = (text: string, findingId: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedPatchId(findingId);
    showToast('Patched code copied to clipboard!');
    setTimeout(() => setCopiedPatchId(null), 2500);
  };

  const handleExportPdf = () => {
    window.print();
  };

  // Filtered findings list
  const filteredFindings = report.findings.filter((f) => {
    const matchSev = severityFilter === 'all' || f.severity.toLowerCase() === severityFilter.toLowerCase();

    // Module categorization matching
    let matchMod = moduleFilter === 'all';
    if (moduleFilter !== 'all') {
      const fCat = (f.category || '').toLowerCase();
      const filterKey = moduleFilter.toLowerCase();
      if (filterKey === 'tech_and_cve') {
        matchMod =
          fCat === 'tech_and_cve' ||
          fCat === 'cve_dependency' ||
          fCat === 'vulnerable_dependency' ||
          fCat === 'sca' ||
          Boolean(f.evidence_metadata?.cve) ||
          Boolean(f.rule_id?.toUpperCase().includes('CVE')) ||
          Boolean(f.title?.toUpperCase().includes('CVE'));
      } else if (filterKey === 'misconfig_default') {
        matchMod =
          fCat === 'misconfig_default' ||
          fCat === 'dast_header' ||
          fCat.includes('misconfig') ||
          Boolean(f.rule_id?.toUpperCase().includes('COOKIE')) ||
          Boolean(f.rule_id?.toUpperCase().includes('HEADER')) ||
          Boolean(f.rule_id?.toUpperCase().includes('CSP')) ||
          Boolean(f.owasp_category?.toLowerCase().includes('misconfiguration'));
      } else if (filterKey === 'nuclei') {
        matchMod = Boolean(f.location?.source_origin?.includes('NUCLEI') || f.rule_id?.startsWith('nuclei-'));
      } else {
        matchMod = fCat === filterKey || fCat.includes(filterKey);
      }
    }

    // Search query matching across title, rule_id, CWE, OWASP, snippet, and risk explanation
    let matchSearch = true;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const blob = [
        f.title,
        f.rule_id,
        f.category,
        f.severity,
        f.cwe_id,
        f.owasp_category,
        f.location?.path,
        f.redacted_code_snippet,
        f.ai_remediation?.risk_explanation,
        f.evidence_metadata ? JSON.stringify(f.evidence_metadata) : '',
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      matchSearch = blob.includes(q);
    }

    return matchSev && matchMod && matchSearch;
  });

  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (rawScore / 100) * circumference;

  const hasReconData = Boolean(
    report.mode !== 'WHITEBOX' &&
    report.recon_summary &&
    (
      (report.recon_summary.open_ports && report.recon_summary.open_ports.length > 0) ||
      report.recon_summary.ssl_summary ||
      (report.recon_summary.sensitive_dirs && report.recon_summary.sensitive_dirs.length > 0) ||
      (report.recon_summary.js_assets && report.recon_summary.js_assets.length > 0)
    )
  );

  const recon = hasReconData ? report.recon_summary : (id === 'demo-fintech' || !id ? DEFAULT_RECON_SUMMARY : null);
  const ssl = recon?.ssl_summary;
  const exposedDbPort = recon?.open_ports?.find((p) => [3306, 5432, 6379, 27017, 21].includes(p.port));
  const hasAiWarning = Boolean(
    report.ai_status_message ||
    report.target_info?.ai_status_message
  );

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Top Header: Breadcrumb + Target Info + Action Buttons */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e1e22]">
        <div className="space-y-1.5">
          <div className="text-xs font-mono text-[#71717a] uppercase flex items-center gap-2">
            <Link to="/dashboard" className="hover:text-white transition-colors">
              PROJECTS
            </Link>
            <span className="text-[#3f3f46]">/</span>
            <span>AUDITS</span>
            <span className="text-[#3f3f46]">/</span>
            <span className="text-white font-medium">#{report.session_id}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white flex items-center gap-3 flex-wrap">
            <span>{report.project_name}</span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-[#111113] border border-[#1e1e22] text-[#ededed]">
              {report.mode}
            </span>
          </h1>
        </div>

        <div className="flex items-center gap-2 flex-wrap print:hidden">
          <button
            type="button"
            onClick={handleExportPdf}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-xs font-mono text-[#d4d4d8] hover:text-white transition-all shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
              <polyline points="14 2 14 8 20 8" />
            </svg>
            <span>Export PDF</span>
          </button>
          <button
            type="button"
            onClick={() => {
              navigator.clipboard?.writeText(window.location.href);
              showToast('Report link copied to clipboard.');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-xs font-mono text-[#d4d4d8] hover:text-white transition-all shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            <span>Share Link</span>
          </button>
          <button
            type="button"
            onClick={() => navigate('/audit/new')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#e5e2e1] hover:bg-white text-black font-medium text-xs font-mono transition-all shadow-sm"
          >
            <span>+ New Audit</span>
          </button>
        </div>
      </div>

      {/* Status Ribbon: 'Audit Complete' + metadata */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-[#71717a] py-2.5 px-4 rounded-xl bg-[#0a0a0a] border border-[#1e1e22]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]" />
          <span className="text-white font-medium">Recon Audit Complete</span>
          <span className="text-[#3f3f46]">·</span>
          <span>Duration: {(report.duration_ms / 1000).toFixed(1)}s</span>
          <span className="text-[#3f3f46]">·</span>
          <span>Target: {report.target_info.target_url || report.target_info.github_repo_url || 'Target Node'}</span>
          {report.target_info?.scan_depth && (
            <>
              <span className="text-[#3f3f46]">·</span>
              <span className="text-[#ededed]">Depth: {report.target_info.scan_depth}</span>
            </>
          )}
          {report.target_info?.entropy_threshold !== undefined && (
            <>
              <span className="text-[#3f3f46]">·</span>
              <span className="text-emerald-400">H(X) ≥ {report.target_info.entropy_threshold}</span>
            </>
          )}
          {report.target_info?.enable_nuclei && (
            <>
              <span className="text-[#3f3f46]">·</span>
              <span className="text-cyan-400">Nuclei: {report.target_info.nuclei_profile?.toUpperCase()} ({report.target_info.nuclei_findings_count ?? 0} hits)</span>
            </>
          )}
        </div>
        <div className="flex items-center gap-3">
          {report.target_info?.js_exposure !== undefined && (
            <>
              <span>JS Deobfuscation: <span className={report.target_info.js_exposure ? "text-emerald-400" : "text-[#71717a]"}>{report.target_info.js_exposure ? 'Active' : 'Bypassed'}</span></span>
              <span className="text-[#3f3f46]">·</span>
            </>
          )}
          <span>Anti-SSRF Verified</span>
          <span className="text-[#3f3f46]">·</span>
          <span className="text-emerald-400">Zero Leak Redacted</span>
        </div>
      </div>

      {/* AI Disconnected / Warning Banner */}
      {(report.ai_status_message || report.target_info?.ai_status_message) && (
        <div className="flex items-center gap-2.5 py-3 px-4 rounded-xl bg-[#111113] border border-amber-500/40 text-amber-300 font-mono text-xs shadow-lg">
          <svg className="w-4 h-4 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <span className="font-semibold text-amber-400">AI Status:</span>
          <span>{report.ai_status_message || report.target_info?.ai_status_message}</span>
        </div>
      )}

      {/* Posture Score (col-span-5) + Summary Breakdown (col-span-7) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Score Card (col-span-5) */}
        <div className="lg:col-span-5 bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 flex flex-col justify-between shadow-2xl">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-[#1e1e22]">
              <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                Security Posture Score
              </span>
              {patchedFindingIds.size > 0 && (
                <button
                  type="button"
                  onClick={resetSimulation}
                  className="px-2.5 py-1 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-xs font-mono text-emerald-400 hover:text-white transition-colors"
                >
                  Reset ({patchedFindingIds.size} Patched)
                </button>
              )}
            </div>

            {/* Gauge & Metrics */}
            <div className="flex flex-col sm:flex-row items-center gap-6 py-6">
              <div className="relative w-36 h-36 flex items-center justify-center shrink-0">
                <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 120 120">
                  <circle
                    cx="60"
                    cy="60"
                    r={radius}
                    fill="transparent"
                    stroke="#1e1e22"
                    strokeWidth="8"
                  />
                  <circle
                    cx="60"
                    cy="60"
                    r={radius}
                    fill="transparent"
                    stroke={
                      rawScore >= 80 ? '#10b981' : rawScore >= 65 ? '#0070f3' : rawScore >= 50 ? '#f59e0b' : '#f43f5e'
                    }
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    className="transition-all duration-700 ease-out"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className="font-mono text-4xl font-bold tracking-tight text-white leading-none">
                    {rawScore}
                  </span>
                  <span className="font-mono text-[10px] text-[#71717a] uppercase tracking-widest mt-1.5">
                    / 100 PTS
                  </span>
                </div>
              </div>

              <div className="flex flex-col items-center sm:items-start space-y-2 text-center sm:text-left">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase ${
                      gradeColor === 'emerald'
                        ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                        : gradeColor === 'blue'
                        ? 'border border-blue-500/30 bg-blue-500/10 text-blue-400'
                        : gradeColor === 'amber'
                        ? 'border border-amber-500/30 bg-amber-500/10 text-amber-400'
                        : 'border border-rose-500/30 bg-rose-500/10 text-rose-400'
                    }`}
                  >
                    Grade {currentGrade}
                  </span>
                </div>
                <div className="text-xs text-[#ededed] font-medium font-mono">
                  {gradeLabel}
                </div>
                <p className="text-xs text-[#71717a] leading-relaxed max-w-[240px]">
                  Formula: 100 - (25×{countCrit} + 15×{countHigh} + 7×{countMed} + 3×{countLow})
                </p>
                {countCrit > 0 && (
                  <div className="text-[11px] font-mono text-rose-400 bg-rose-950/30 px-2 py-0.5 rounded border border-rose-800/40 flex items-center gap-1.5">
                    <svg className="w-3.5 h-3.5 shrink-0 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    <span>Hard Rule: Critical Present → Max Grade D</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22] text-xs font-mono text-[#71717a] flex items-center justify-between">
            <span>Simulate patches on findings to recalculate score in real-time</span>
            <span className="text-emerald-400 font-semibold">
              {patchedFindingIds.size > 0 ? `+${100 - rawScore === 0 ? 'Max Score' : 50} Pts Simulated` : ''}
            </span>
          </div>
        </div>

        {/* Audit Summary & Scope (col-span-7) */}
        <div className="lg:col-span-7 bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 flex flex-col justify-between shadow-2xl space-y-6">
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-[#1e1e22]">
              <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                Audit Scope &amp; Severity Breakdown
              </span>
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                Surface Recon
              </span>
            </div>

            {/* Severity Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22]">
                <span className="font-mono text-[10px] text-rose-400 uppercase tracking-wider block">
                  Critical (-25)
                </span>
                <span className="font-mono text-2xl font-bold text-white mt-1 block">
                  {countCrit}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22]">
                <span className="font-mono text-[10px] text-amber-400 uppercase tracking-wider block">
                  High (-15)
                </span>
                <span className="font-mono text-2xl font-bold text-white mt-1 block">
                  {countHigh}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22]">
                <span className="font-mono text-[10px] text-yellow-400 uppercase tracking-wider block">
                  Medium (-7)
                </span>
                <span className="font-mono text-2xl font-bold text-white mt-1 block">
                  {countMed}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22]">
                <span className="font-mono text-[10px] text-blue-400 uppercase tracking-wider block">
                  Low (-3)
                </span>
                <span className="font-mono text-2xl font-bold text-white mt-1 block">
                  {countLow}
                </span>
              </div>
            </div>

            {/* Detected Tech Stack */}
            <div className="space-y-2">
              <span className="font-mono text-[11px] text-[#71717a] uppercase tracking-wider block">
                Target URL &amp; Fingerprint Architecture
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(report.target_info.detected_tech_stack || ['FastAPI', 'React', 'OSV.dev', 'Tree-sitter']).map((tech) => (
                  <span
                    key={tech}
                    className="px-2.5 py-1 rounded-lg border border-[#1e1e22] bg-[#111113] text-[#d4d4d8] font-mono text-xs"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-[#1e1e22] flex items-center justify-between text-[#71717a] font-mono text-xs">
            <span>Auto-Redaction Active</span>
            <span>Audited: {new Date(report.audited_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* ATTACK SURFACE & RECONNAISSANCE TELEMETRY                                */}
      {/* ========================================================================= */}
      {recon && (hasReconData || id === 'demo-fintech' || !id) ? (
        <>
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[#1e1e22]">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider font-mono text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-[#a1a1aa]" />
                  <span>Surface Reconnaissance &amp; Exposure Telemetry</span>
                </h2>
                <p className="text-xs text-[#71717a] font-mono mt-0.5">
                  Host evaluation across network ports, TLS lifecycle, software fingerprinting, and application endpoints
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
                  Non-Destructive Recon
                </span>
              </div>
            </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
          {/* Card 1: TLS / SSL Certificate */}
          <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                <div className="flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                    TLS &amp; Cryptography
                  </span>
                </div>
                {ssl?.expired ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/10 border border-rose-500/30 text-rose-400">
                    EXPIRED
                  </span>
                ) : (ssl?.days_left ?? 90) < 14 ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400">
                    EXPIRING SOON
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    VALID
                  </span>
                )}
              </div>

              {/* Status Header */}
              <div className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-1">
                <span className="text-[11px] font-mono text-[#71717a] block">Certificate Status:</span>
                <div className="flex items-center gap-2">
                  {ssl?.expired ? (
                    <span className="text-rose-400 font-mono font-medium text-xs flex items-center gap-1.5">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Expired ({Math.abs(ssl?.days_left || 0)} days ago)</span>
                    </span>
                  ) : (
                    <span className="text-emerald-400 font-mono font-medium text-xs flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Active ({ssl?.days_left ?? 84} days remaining)</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Protocol & Issuer Details */}
              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-[#ededed]">
                  <span className="text-[#71717a]">Protocol:</span>
                  <span className="px-2 py-0.5 rounded bg-black border border-[#1e1e22] text-[#ededed] font-semibold">
                    {ssl?.protocol || 'TLSv1.3'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[#ededed]">
                  <span className="text-[#71717a]">Issuer:</span>
                  <span className="truncate max-w-[160px] text-right text-[#d4d4d8]" title={ssl?.issuer}>
                    {ssl?.issuer || "Let's Encrypt Authority"}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[#ededed]">
                  <span className="text-[#71717a]">HTTPS Redirect:</span>
                  <span className={ssl?.redirect_https ? 'text-emerald-400' : 'text-amber-400'}>
                    {ssl?.redirect_https ? 'Enforced' : 'Missing'}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#1e1e22] text-[11px] font-mono text-[#71717a]">
              Direct socket TLS handshake evaluation.
            </div>
          </div>

          {/* Card 2: Port & Network Surface */}
          <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                <div className="flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                    Network Ports
                  </span>
                </div>
                <span className="text-[11px] font-mono text-[#71717a]">
                  {recon.open_ports.length} Open / 12 Probed
                </span>
              </div>

              {/* Alert if Database Port is Open */}
              {exposedDbPort && (
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span className="font-medium">Exposed Service: {exposedDbPort.service} (Port {exposedDbPort.port})</span>
                </div>
              )}

              {/* Port Pills */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-mono text-[#71717a] block">Discovered Open Ports:</span>
                <div className="flex flex-wrap gap-1.5">
                  {recon.open_ports.map((p) => {
                    const isDb = [3306, 5432, 6379, 27017, 21].includes(p.port);
                    const isDev = [3000, 8000, 8080, 8443].includes(p.port);
                    return (
                      <span
                        key={p.port}
                        className={`px-2.5 py-1 rounded text-xs font-mono flex items-center gap-1.5 ${
                          isDb
                            ? 'bg-rose-500/10 border border-rose-500/30 text-rose-300 font-medium'
                            : isDev
                            ? 'bg-amber-500/10 border border-amber-500/30 text-amber-300'
                            : 'bg-[#111113] border border-[#1e1e22] text-[#ededed]'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            isDb ? 'bg-rose-500' : isDev ? 'bg-amber-400' : 'bg-emerald-400'
                          }`}
                        />
                        <span>{p.port} · {p.service}</span>
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#1e1e22] text-[11px] font-mono text-[#71717a]">
              Async socket probe with 1.5s timeout.
            </div>
          </div>

          {/* Card 3: Software Stack & CVEs */}
          <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                <div className="flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                    Software Stack &amp; CVEs
                  </span>
                </div>
                <span className="text-[11px] font-mono text-amber-400">
                  {recon.detected_tech.filter((t) => t.cve_count > 0 || t.outdated).length} Flagged
                </span>
              </div>

              {/* Technologies List */}
              <div className="space-y-2">
                {recon.detected_tech.map((tech) => (
                  <div
                    key={tech.name}
                    className="p-2.5 rounded-lg bg-[#111113] border border-[#1e1e22] flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <span className="font-medium text-white">{tech.name}</span>{' '}
                      <span className="text-[#71717a]">{tech.version || ''}</span>
                    </div>
                    {tech.cve_count > 0 ? (
                      <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] font-medium flex items-center gap-1">
                        <ShieldAlert className="w-3 h-3 text-rose-400" />
                        <span>{tech.cve_count} CVE</span>
                      </span>
                    ) : tech.outdated ? (
                      <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px]">
                        Outdated
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px]">
                        Current
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-[#1e1e22] text-[11px] font-mono text-[#71717a]">
              Header and DOM fingerprinting matched to OSV.dev.
            </div>
          </div>
        </div>

        {/* 2 Additional Cards: Sensitive Endpoints & DOM Comments */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch pt-2">
          {/* Card 4: Sensitive Paths & Endpoints */}
          <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                <div className="flex items-center gap-2">
                  <FolderSearch className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                    Sensitive Paths &amp; Resources
                  </span>
                </div>
                <span className="text-[11px] font-mono text-[#71717a]">
                  Soft-404 Validated
                </span>
              </div>

              <div className="space-y-2">
                {recon.sensitive_dirs.map((dir) => (
                  <div
                    key={dir.path}
                    className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-1.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-white">{dir.path}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-medium font-mono ${
                          dir.status === 403 || dir.risk === 'BLOCKED' || dir.risk === 'FORBIDDEN'
                            ? 'bg-[#1e1e22] border border-[#27272a] text-[#a1a1aa]'
                            : dir.risk === 'CRITICAL'
                            ? 'bg-rose-500/10 border border-rose-500/30 text-rose-400'
                            : dir.risk === 'HIGH'
                            ? 'bg-amber-500/10 border border-amber-500/30 text-amber-400'
                            : 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
                        }`}
                      >
                        HTTP {dir.status} · {dir.status === 403 ? 'FORBIDDEN (BLOCKED)' : dir.risk}
                      </span>
                    </div>
                    {dir.detail && <p className="text-[#a1a1aa] text-[11px]">{dir.detail}</p>}
                    {dir.disallowed_routes && dir.disallowed_routes.filter(Boolean).length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap pt-1">
                        <span className="text-[#71717a] text-[10px]">Disallow:</span>
                        {dir.disallowed_routes.filter(Boolean).map((r) => (
                          <span
                            key={r}
                            className="px-1.5 py-0.5 rounded bg-black border border-[#1e1e22] text-[#d4d4d8] text-[10px]"
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-[#1e1e22] text-[11px] font-mono text-[#71717a]">
              Probed against 20 critical paths using baseline comparison.
            </div>
          </div>

          {/* Card 5: DOM Comments & Leaked Metadata */}
          <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                <div className="flex items-center gap-2">
                  <FileCode2 className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                    DOM Comments &amp; Metadata
                  </span>
                </div>
                <span className="text-[11px] font-mono text-emerald-400">
                  Auto-Redacted
                </span>
              </div>

              <div className="space-y-2">
                {recon.html_leaks.map((leak, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-1.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[#ededed] font-medium">Comment #{idx + 1}</span>
                      <span className="text-[10px] text-[#71717a]">Masked</span>
                    </div>
                    <pre className="text-[#d4d4d8] bg-black p-2 rounded border border-[#1e1e22] text-[11px] overflow-x-auto">
                      <code>{leak.snippet || 'Sensitif comment detected'}</code>
                    </pre>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-[#1e1e22] text-[11px] font-mono text-[#71717a]">
              HTML comment extraction, developer notes, and contact metadata.
            </div>
          </div>
        </div>
      </div>

      {/* Modern Web & JavaScript Asset Deep Reconnaissance Panel */}
      {recon.js_assets && recon.js_assets.length > 0 && (
        <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#1e1e22]">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Boxes className="w-4 h-4 text-[#a1a1aa]" />
                <h3 className="text-sm font-semibold uppercase tracking-wider font-mono text-white">
                  Modern Web &amp; JavaScript Deep Reconnaissance
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-500/10 border border-blue-500/30 text-blue-400">
                  Recursive Crawl (Depth 2)
                </span>
              </div>
              <p className="text-xs text-[#71717a] font-mono">
                Deep inspection of client-side JavaScript bundles: sub-chunk mapping, unminified source map resolution, hidden API route extraction, and secret token detection.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-2.5 py-1 rounded bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                {recon.js_assets.length} Bundles
              </span>
              <span className="px-2.5 py-1 rounded bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                {recon.js_assets.reduce((acc, curr) => acc + (curr.discovered_endpoints?.length || 0), 0)} Endpoints Mapped
              </span>
              {recon.js_assets.some((a) => a.sourcemap_exposed) && (
                <span className="px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 font-semibold">
                  Source Maps Exposed
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {recon.js_assets.map((asset, idx) => (
              <div
                key={idx}
                className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] flex flex-col justify-between space-y-3 font-mono text-xs"
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <FileCode2 className="w-4 h-4 text-[#a1a1aa] shrink-0" />
                      <span className="text-white font-medium truncate" title={asset.filename}>
                        {asset.filename}
                      </span>
                    </div>
                    <span className="text-[11px] text-[#71717a] shrink-0">
                      {asset.size_kb} KB
                    </span>
                  </div>

                  <div className="text-[11px] text-[#71717a] break-all truncate" title={asset.url}>
                    {asset.url}
                  </div>

                  {/* Badges for SourceMap & Secrets */}
                  <div className="flex flex-wrap gap-2 pt-1">
                    {asset.sourcemap_exposed ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" />
                        <span>Source Map (.map) Exposed</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-black border border-[#1e1e22] text-[#71717a]">
                        No Public Map
                      </span>
                    )}

                    {asset.secrets_found > 0 ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center gap-1">
                        <ShieldAlert className="w-3 h-3" />
                        <span>{asset.secrets_found} Secret Found</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-black border border-[#1e1e22] text-emerald-400">
                        Secrets Clean
                      </span>
                    )}
                  </div>

                  {/* Discovered Sub Chunks */}
                  {asset.sub_chunks && asset.sub_chunks.length > 0 && (
                    <div className="space-y-1 pt-2 border-t border-[#1e1e22]">
                      <span className="text-[10px] text-[#71717a] uppercase tracking-wider block">
                        Linked Dynamic Chunks:
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {asset.sub_chunks.map((chunk, cIdx) => (
                          <span
                            key={cIdx}
                            className="px-1.5 py-0.5 rounded bg-black border border-[#1e1e22] text-[#d4d4d8] text-[10px]"
                          >
                            {chunk}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Discovered Endpoints */}
                  {asset.discovered_endpoints && asset.discovered_endpoints.length > 0 && (
                    <div className="space-y-1 pt-2 border-t border-[#1e1e22]">
                      <span className="text-[10px] text-[#71717a] uppercase tracking-wider flex items-center gap-1">
                        <Braces className="w-3 h-3 text-[#a1a1aa]" />
                        <span>Internal API Routes Mapped ({asset.discovered_endpoints.length}):</span>
                      </span>
                      <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                        {asset.discovered_endpoints.map((ep, eIdx) => (
                          <span
                            key={eIdx}
                            className="px-1.5 py-0.5 rounded bg-black border border-[#1e1e22] text-blue-400 text-[10px]"
                          >
                            {ep}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {asset.sourcemap_url && (
                  <div className="pt-2 border-t border-[#1e1e22] flex items-center justify-between text-[11px] text-[#71717a]">
                    <span>Source Map URL:</span>
                    <a
                      href={asset.sourcemap_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-amber-400 hover:underline flex items-center gap-1 truncate max-w-[200px]"
                    >
                      <span className="truncate">{asset.sourcemap_url.split('/').pop()}</span>
                      <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
        </>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[#1e1e22]">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider font-mono text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-[#a1a1aa]" />
                <span>Whitebox Source &amp; System Logic Telemetry</span>
              </h2>
              <p className="text-xs text-[#71717a] font-mono mt-0.5">
                Evaluation of system architecture, API route controllers, state mutation boundaries, and AI-assisted logic flaw audits
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
                Source Logic SAST
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
            {/* Card 1: Audited Target Repository */}
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                  <div className="flex items-center gap-2">
                    <GitBranch className="w-3.5 h-3.5 text-[#a1a1aa]" />
                    <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                      Audited Repository
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    ANALYZED
                  </span>
                </div>
                <div className="space-y-2">
                  <div className="text-xs text-[#71717a] font-mono">Target Source:</div>
                  <div className="text-sm font-mono text-white font-medium break-all">
                    {report.target_info?.github_repo_url || report.target_info?.target_url || 'Target Repository'}
                  </div>
                  <div className="text-xs text-[#71717a] font-mono pt-1">
                    Audited Branch: <span className="text-[#ededed]">{report.target_info?.branch || 'main'}</span>
                  </div>
                </div>
              </div>
              <p className="text-[11px] text-[#71717a] font-mono border-t border-[#1e1e22] pt-3">
                Source code analyzed for state mutation flaws, authorization bypasses, and injection sinks.
              </p>
            </div>

            {/* Card 2: AI Logic Engine Status */}
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-[#a1a1aa]" />
                    <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                      AI Logic Engine
                    </span>
                  </div>
                  {hasAiWarning ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400">
                      HEURISTIC FALLBACK
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                      ONLINE ACTIVE
                    </span>
                  )}
                </div>
                <div className="space-y-2">
                  <div className="text-xs text-[#71717a] font-mono">Inference Engine:</div>
                  <div className="text-sm font-mono text-white font-medium">
                    {hasAiWarning ? 'Offline Heuristic Engine' : 'Google Gemini Flash SAST'}
                  </div>
                  <div className="text-xs text-[#71717a] font-mono pt-1">
                    Scope: <span className="text-[#ededed]">OWASP Top 10 (XSS, BOLA/IDOR, File Upload, Mass Assignment)</span>
                  </div>
                </div>
              </div>
              <p className="text-[11px] text-[#71717a] font-mono border-t border-[#1e1e22] pt-3">
                Automated vulnerability reasoning coupled with proactive remediation patch synthesis.
              </p>
            </div>

            {/* Card 3: Detected Architecture & Findings Summary */}
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-5 flex flex-col justify-between shadow-xl space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#a1a1aa]" />
                    <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                      System Architecture
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-white/10 border border-white/20 text-[#ededed]">
                    {report.findings.filter((f) => ['SYSTEM_LOGIC', 'DOM_XSS'].includes(f.category) || f.location?.source_origin?.includes('WHITEBOX')).length} SAST Findings
                  </span>
                </div>
                <div className="space-y-1.5">
                  <div className="text-xs text-[#71717a] font-mono">Detected Frameworks:</div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {(report.target_info?.detected_tech_stack || ['Python', 'Flask', 'React']).map((tech: string) => (
                      <span
                        key={tech}
                        className="px-2 py-0.5 text-[11px] font-mono rounded bg-[#111113] border border-[#1e1e22] text-[#ededed]"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <p className="text-[11px] text-[#71717a] font-mono border-t border-[#1e1e22] pt-3">
                Zero leak sanitization active across tokens, internal routes, and credentials.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FINDINGS FILTER TABS (Severity & Module)                                  */}
      {/* ========================================================================= */}
      <div className="space-y-3 pt-4 border-t border-[#1e1e22]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <h3 className="text-sm font-semibold uppercase tracking-wider font-mono text-white">
              Detailed Audit Findings ({report.findings.length})
            </h3>
            <p className="text-xs text-[#71717a] font-mono">
              Click "Simulate Patch" on any finding to test score improvement in real-time
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-[#0a0a0a] border border-[#1e1e22]">
            {[
              { key: 'all', label: `All (${report.findings.length})` },
              { key: 'critical', label: `Critical (${report.findings.filter((f) => f.severity === 'CRITICAL').length})`, dot: 'bg-rose-500' },
              { key: 'high', label: `High (${report.findings.filter((f) => f.severity === 'HIGH').length})`, dot: 'bg-amber-500' },
              { key: 'medium', label: `Medium (${report.findings.filter((f) => f.severity === 'MEDIUM').length})`, dot: 'bg-yellow-500' },
              { key: 'low', label: `Low (${report.findings.filter((f) => f.severity === 'LOW').length})`, dot: 'bg-blue-500' },
            ].map((tab) => (
              <button
                key={tab.key}
                type="button"
                onClick={() => setSeverityFilter(tab.key)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center gap-1.5 ${
                  severityFilter === tab.key
                    ? 'bg-white text-black font-semibold shadow-sm'
                    : 'text-[#71717a] hover:text-white'
                }`}
              >
                {tab.dot && <span className={`w-1.5 h-1.5 rounded-full ${tab.dot}`} />}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Module Filter Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono">
          <span className="text-[#71717a]">Module:</span>
          {[
            { key: 'all', label: 'All Modules' },
            { key: 'NUCLEI', label: 'Nuclei DAST' },
            { key: 'PORT_SCAN', label: 'Port Scanner' },
            { key: 'DIR_FINDER', label: 'Dir Finder' },
            { key: 'TECH_AND_CVE', label: 'Tech & CVE' },
            { key: 'HTML_METADATA', label: 'HTML Leaks' },
            { key: 'JS_CRAWLER_SECRET', label: 'JS Secrets' },
            { key: 'MISCONFIG_DEFAULT', label: 'Misconfig' },
          ].map((m) => (
            <button
              key={m.key}
              type="button"
              onClick={() => setModuleFilter(m.key)}
              className={`px-2.5 py-1 rounded-lg border text-xs transition-colors ${
                moduleFilter === m.key
                  ? 'border-blue-500/40 bg-blue-500/10 text-blue-400 font-semibold'
                  : 'border-[#1e1e22] bg-[#0a0a0a] text-[#71717a] hover:text-white'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {/* Search findings input */}
        <div className="relative pt-1">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search findings (e.g. cookie, security header, Content Security Policy, CVE, port)..."
            aria-label="Search findings"
            data-testid="findings-search-input"
            className="w-full bg-[#0a0a0a] border border-[#1e1e22] focus:border-[#3f3f46] rounded-xl px-4 py-2 text-xs font-mono text-white placeholder-[#71717a] outline-none transition-all shadow-inner"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-3 text-xs font-mono text-[#71717a] hover:text-white"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.map((finding) => {
          const isPatched = patchedFindingIds.has(finding.id);
          const activeTab = activeTabByFinding[finding.id] || 'summary';

          const sevBadge =
            finding.severity === 'CRITICAL'
              ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
              : finding.severity === 'HIGH'
              ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
              : finding.severity === 'MEDIUM'
              ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
              : 'bg-blue-500/10 text-blue-400 border-blue-500/20';

          return (
            <div
              key={finding.id}
              className={`bg-[#0a0a0a] border rounded-xl overflow-hidden shadow-xl transition-all ${
                isPatched ? 'border-emerald-500/40 opacity-75' : 'border-[#1e1e22]'
              }`}
            >
              {/* Finding Card Header */}
              <div className="p-4 sm:p-5 border-b border-[#1e1e22] flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111113]/40">
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className={`px-2 py-0.5 rounded-full border font-bold ${sevBadge}`}>
                      {finding.severity}
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-[#1e1e22] bg-[#111113] text-[#ededed]">
                      CVSS {finding.cvss_score}
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-[#1e1e22] bg-[#111113] text-[#71717a]">
                      {finding.cwe_id}
                    </span>
                    {(() => {
                      const cveMatch =
                        finding.evidence_metadata?.cve ||
                        finding.rule_id?.match(/CVE-\d{4}-\d+/i)?.[0] ||
                        finding.title?.match(/CVE-\d{4}-\d+/i)?.[0];
                      if (cveMatch) {
                        return (
                          <span className="px-2 py-0.5 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-400 font-semibold font-mono text-[10px]">
                            {cveMatch}
                          </span>
                        );
                      }
                      return null;
                    })()}
                    {(finding.location?.source_origin?.includes('NUCLEI') || finding.rule_id?.startsWith('nuclei-')) && (
                      <span className="px-2 py-0.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 font-semibold text-[10px]">
                        {finding.location?.source_origin === 'RECON_AND_NUCLEI' ? 'RECON + NUCLEI' : 'NUCLEI DAST'}
                      </span>
                    )}
                    <span className="text-[#52525b]">{finding.location.path}</span>
                  </div>
                  <h3 className="text-base font-semibold text-white tracking-tight">
                    {finding.title}
                  </h3>
                </div>

                <div className="flex items-center gap-2 self-start md:self-center shrink-0">
                  <button
                    type="button"
                    onClick={() => toggleSimulatePatch(finding.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
                      isPatched
                        ? 'bg-emerald-500 text-black hover:bg-emerald-400'
                        : 'bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed]'
                    }`}
                  >
                    {isPatched ? (
                      <>
                        <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                        <span>Patch Simulated</span>
                      </>
                    ) : (
                      <>
                        <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                        </svg>
                        <span>Simulate Patch</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Sub-tabs: 1. Risk Summary, 2. Code Evidence, 3. AI Remediation */}
              <div className="p-4 sm:p-5 space-y-4">
                <div className="flex items-center gap-6 border-b border-[#1e1e22] text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setActiveTabByFinding((prev) => ({ ...prev, [finding.id]: 'summary' }))}
                    className={`pb-2 border-b-2 font-medium transition-colors ${
                      activeTab === 'summary' ? 'border-white text-white' : 'border-transparent text-[#71717a] hover:text-white'
                    }`}
                  >
                    1. Risk Summary &amp; Steps
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTabByFinding((prev) => ({ ...prev, [finding.id]: 'evidence' }))}
                    className={`pb-2 border-b-2 font-medium transition-colors ${
                      activeTab === 'evidence' ? 'border-white text-white' : 'border-transparent text-[#71717a] hover:text-white'
                    }`}
                  >
                    2. Code Evidence (Redacted)
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTabByFinding((prev) => ({ ...prev, [finding.id]: 'diff' }))}
                    className={`pb-2 border-b-2 font-medium transition-colors ${
                      activeTab === 'diff' ? 'border-white text-white' : 'border-transparent text-[#71717a] hover:text-white'
                    }`}
                  >
                    3. AI Remediation Patch ({finding.ai_remediation.model})
                  </button>
                </div>

                {/* Tab 1: Risk Summary & Deep Threat Modeling */}
                {activeTab === 'summary' && (() => {
                  const attackScenario = (finding.ai_remediation as any)?.attack_scenario || (finding.evidence_metadata as any)?.attack_scenario;
                  const blastRadius = (finding.ai_remediation as any)?.blast_radius || (finding.evidence_metadata as any)?.blast_radius;
                  const exploitChain = (finding.ai_remediation as any)?.exploit_chain || (finding.evidence_metadata as any)?.exploit_chain;
                  const prerequisites = (finding.ai_remediation as any)?.prerequisites || (finding.evidence_metadata as any)?.prerequisites;

                  return (
                    <div className="space-y-3 pt-2 text-xs">
                      {/* Risk explanation */}
                      <p className="text-[#a1a1aa] leading-relaxed font-sans">
                        {finding.ai_remediation.risk_explanation}
                      </p>

                      {/* Adversary Attack Scenario */}
                      {attackScenario && (
                        <div className="p-3.5 rounded-lg border border-rose-500/20 bg-[#0c0507] space-y-1.5 font-sans">
                          <div className="flex items-center gap-1.5 text-rose-400 font-semibold font-mono text-xs">
                            <Bug className="w-3.5 h-3.5 shrink-0" />
                            <span>Adversary Attack Scenario</span>
                          </div>
                          <p className="text-[#ededed] leading-relaxed text-xs">
                            {attackScenario}
                          </p>
                        </div>
                      )}

                      {/* Blast Radius & Potential Impact */}
                      {blastRadius && (
                        <div className="p-3.5 rounded-lg border border-amber-500/20 bg-[#0c0a06] space-y-1.5 font-sans">
                          <div className="flex items-center gap-1.5 text-amber-400 font-semibold font-mono text-xs">
                            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                            <span>Potential Impact &amp; Blast Radius</span>
                          </div>
                          <p className="text-[#ededed] leading-relaxed text-xs">
                            {blastRadius}
                          </p>
                        </div>
                      )}

                      {/* Exploit Chain & Prerequisites */}
                      {(exploitChain || prerequisites) && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                          {exploitChain && (
                            <div className="p-3 rounded-lg border border-[#1e1e22] bg-[#050505] space-y-1">
                              <span className="text-[10px] text-cyan-400 uppercase tracking-wider flex items-center gap-1.5 font-semibold">
                                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                                </svg>
                                <span>Exploit Chain Narrative</span>
                              </span>
                              <span className="text-[#a1a1aa] leading-relaxed block">
                                {exploitChain}
                              </span>
                            </div>
                          )}
                          {prerequisites && (
                            <div className="p-3 rounded-lg border border-[#1e1e22] bg-[#050505] space-y-1">
                              <span className="text-[10px] text-purple-400 uppercase tracking-wider flex items-center gap-1.5 font-semibold">
                                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <circle cx="12" cy="12" r="10" />
                                  <line x1="22" y1="12" x2="18" y2="12" />
                                  <line x1="6" y1="12" x2="2" y2="12" />
                                  <line x1="12" y1="6" x2="12" y2="2" />
                                  <line x1="12" y1="22" x2="12" y2="18" />
                                </svg>
                                <span>Attacker Prerequisites</span>
                              </span>
                              <span className="text-[#a1a1aa] leading-relaxed block">
                                {prerequisites}
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Recommended Remediation Steps */}
                      <div className="p-3 rounded-lg border border-[#1e1e22] bg-[#050505] space-y-2 font-mono">
                        <span className="text-[10px] text-[#71717a] uppercase tracking-wider block">
                          Recommended Remediation Steps
                        </span>
                        <ul className="space-y-1.5 text-[#ededed]">
                          {finding.ai_remediation.remediation_steps.map((step, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <span className="text-emerald-400 font-bold">{idx + 1}.</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  );
                })()}

                {/* Tab 2: Evidence Code */}
                {activeTab === 'evidence' && (
                  <div className="space-y-3 pt-2 font-mono text-xs">
                    {finding.evidence_metadata?.entropy_score && (
                      <div className="p-3 rounded-lg border border-[#1e1e22] bg-[#050505] flex items-center justify-between">
                        <span className="text-[#71717a]">Shannon Entropy H(X):</span>
                        <span className="text-rose-400 font-semibold">
                          {finding.evidence_metadata.entropy_score} / 8.0 bits (Exceeds threshold {finding.evidence_metadata.threshold || 4.2})
                        </span>
                      </div>
                    )}
                    <div className="rounded-lg border border-[#1e1e22] bg-black p-3 space-y-2 overflow-x-auto">
                      <div className="flex items-center justify-between text-[#71717a] pb-2 border-b border-[#1e1e22]">
                        <span>AST Taint / Secret Evidence</span>
                        <span>{finding.location.path}:{finding.location.line_start || 1}</span>
                      </div>
                      <pre className="text-[#ededed] leading-relaxed">
                        <code>{finding.redacted_code_snippet}</code>
                      </pre>
                    </div>
                  </div>
                )}

                {/* Tab 3: AI Code Patch Diff */}
                {activeTab === 'diff' && (
                  <div className="space-y-3 pt-2 font-mono text-xs">
                    {finding.ai_remediation?.warning && (
                      <div className="p-3 rounded-lg border border-amber-500/30 bg-[#161618] text-amber-300 flex items-center gap-2">
                        <svg className="w-4 h-4 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                        <span>{finding.ai_remediation.warning}</span>
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Before Box */}
                      <div className="rounded-lg border border-rose-500/20 bg-black p-3 space-y-2">
                        <div className="text-rose-400 font-semibold flex items-center gap-1.5">
                          <span>✕ Vulnerable (Current Implementation)</span>
                        </div>
                        <pre className="text-[#d4d4d8] overflow-x-auto leading-relaxed">
                          <code>{finding.ai_remediation.code_patch.original_code}</code>
                        </pre>
                      </div>

                      {/* After Box */}
                      <div className="rounded-lg border border-emerald-500/20 bg-black p-3 space-y-2">
                        <div className="text-emerald-400 font-semibold flex items-center gap-1.5">
                          <span>✓ AI Remediation Diff (Safe Implementation)</span>
                        </div>
                        <pre className="text-[#d4d4d8] overflow-x-auto leading-relaxed">
                          <code>{finding.ai_remediation.code_patch.patched_code}</code>
                        </pre>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs text-[#71717a]">
                      <span>Model: {finding.ai_remediation.model}</span>
                      <button
                        type="button"
                        onClick={() => copyCode(finding.ai_remediation.code_patch.patched_code, finding.id)}
                        className="px-3 py-1 rounded bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-white font-mono text-xs transition-colors"
                      >
                        {copiedPatchId === finding.id ? '✓ Copied!' : 'Copy Patched Code'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50">
          <div className="px-4 py-3 rounded-xl bg-[#111113] border border-[#1e1e22] shadow-2xl flex items-center gap-3 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-white">{toastMessage}</span>
          </div>
        </div>
      )}
    </div>
  );
}
