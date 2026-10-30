import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Terminal,
  Code2,
  Cpu,
  Layers,
  Check,
  Copy,
  BookOpen,
  Zap,
  Server,
  Lock,
  Search,
  ChevronRight,
  Radio,
  CheckCircle2,
  ExternalLink,
  Globe,
  Key,
  Database,
} from 'lucide-react';

interface CodeSnippetProps {
  code: string;
  language?: string;
}

const CodeSnippet: React.FC<CodeSnippetProps> = ({ code, language = 'bash' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group my-3 rounded-lg border border-[#1e1e22] bg-[#0c0c0e] overflow-hidden font-mono text-xs">
      <div className="flex items-center justify-between px-3.5 py-1.5 border-b border-[#1e1e22] bg-[#111113] text-[#71717a]">
        <span className="text-[11px] uppercase tracking-wider">{language}</span>
        <button
          onClick={handleCopy}
          type="button"
          className="flex items-center gap-1 hover:text-white transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-[10px] text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span className="text-[10px]">Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-4 text-[#ededed] overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
};

export const DocsPage: React.FC = () => {
  const [activeSection, setActiveSection] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');

  const sections = [
    { id: 'overview', title: 'Architecture Overview', icon: BookOpen },
    { id: 'modes', title: 'Audit Execution Modes', icon: Layers },
    { id: 'recon', title: 'Recon & Attack Surface', icon: Globe },
    { id: 'nuclei', title: 'Nuclei DAST Active Probing', icon: Zap },
    { id: 'sast', title: 'AST Taint & Source Logic', icon: Code2 },
    { id: 'entropy', title: 'Shannon Entropy Secret Mining', icon: Lock },
    { id: 'authscan', title: 'Authenticated Scanning & Headers', icon: Key },
    { id: 'database', title: 'Supabase & Hybrid Storage', icon: Database },
    { id: 'tuning', title: 'Engine Tuning & Heuristics', icon: Cpu },
    { id: 'api', title: 'REST API & Presets Reference', icon: Terminal },
    { id: 'docker', title: 'Docker & CLI Deployment', icon: Server },
  ];

  const filteredSections = sections.filter(
    (s) =>
      s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-black text-[#ededed] font-sans antialiased">
      {/* Top Banner Header */}
      <div className="border-b border-[#1e1e22] bg-[#0a0a0a]/80 backdrop-blur-md sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#111113] border border-[#1e1e22] flex items-center justify-center text-white">
              <BookOpen className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold font-mono uppercase tracking-wider text-white">
                  SecAudit Platform Documentation
                </h1>
                <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  v2.4.0
                </span>
              </div>
              <p className="text-xs text-[#71717a] font-mono">
                Technical reference, multi-engine security specifications, Supabase persistence, and API schemas.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-64">
              <Search className="w-3.5 h-3.5 text-[#71717a] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search topics (e.g. recon, nuclei, supabase)..."
                className="w-full h-8 pl-8 pr-3 text-xs font-mono bg-[#111113] border border-[#1e1e22] rounded-md text-white placeholder-[#71717a] focus:outline-none focus:border-[#3f3f46] transition-colors"
              />
            </div>

            <Link
              to="/audit/new"
              className="h-8 px-3 text-xs font-mono font-medium bg-white text-black rounded-md hover:bg-[#ededed] transition-colors flex items-center gap-1.5 shrink-0"
            >
              <span>Launch Audit</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* Main Documentation Grid Layout */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left Sidebar Table of Contents */}
          <aside className="lg:col-span-3 space-y-4 lg:sticky lg:top-24">
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-3 space-y-1">
              <div className="px-3 py-2 text-[10px] font-mono uppercase text-[#71717a] tracking-wider border-b border-[#1e1e22] mb-1">
                Navigation Topics
              </div>
              {filteredSections.map((s) => {
                const Icon = s.icon;
                const isActive = activeSection === s.id;
                return (
                  <button
                    key={s.id}
                    onClick={() => setActiveSection(s.id)}
                    type="button"
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono text-left transition-colors ${
                      isActive
                        ? 'bg-[#161618] text-white border border-[#27272a]'
                        : 'text-[#a1a1aa] hover:bg-[#111113] hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-white' : 'text-[#71717a]'}`} />
                      <span className="truncate">{s.title}</span>
                    </div>
                    {isActive && <ChevronRight className="w-3.5 h-3.5 text-white shrink-0" />}
                  </button>
                );
              })}
            </div>

            {/* Quick Spec Card */}
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-4 space-y-3 font-mono text-xs">
              <div className="text-[11px] font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-emerald-400" />
                <span>Runtime Platform Metrics</span>
              </div>
              <div className="space-y-1.5 text-[11px] text-[#71717a]">
                <div className="flex justify-between">
                  <span>Engine Binary:</span>
                  <span className="text-white">Nuclei v3.3+</span>
                </div>
                <div className="flex justify-between">
                  <span>Recon Engine:</span>
                  <span className="text-white">DNS / Port / WAF</span>
                </div>
                <div className="flex justify-between">
                  <span>Curated Templates:</span>
                  <span className="text-white">114 Rules (OWASP)</span>
                </div>
                <div className="flex justify-between">
                  <span>Inference SAST:</span>
                  <span className="text-white">Gemini Flash Lite</span>
                </div>
                <div className="flex justify-between">
                  <span>Persistence:</span>
                  <span className="text-emerald-400">Supabase + SQLite</span>
                </div>
                <div className="flex justify-between">
                  <span>Data Retention:</span>
                  <span className="text-emerald-400">0 Days Plaintext Secret</span>
                </div>
              </div>
            </div>
          </aside>

          {/* Right Main Content Panel */}
          <main className="lg:col-span-9 space-y-12">
            {/* Section 1: Architecture Overview */}
            {(activeSection === 'overview' || searchQuery) && (
              <section id="overview" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                  <Shield className="w-4 h-4" />
                  <span>CORE PLATFORM ARCHITECTURE</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Autonomous Multi-Engine Security Auditing
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Unified defense-in-depth posture analysis combining Network Recon, Nuclei DAST, AST Taint SAST, and AI Remediation.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    SecAudit is an enterprise-grade autonomous security auditing platform engineered to evaluate modern web applications and microservice repositories before threat actors identify them. Rather than isolating static analysis and runtime testing, SecAudit unifies external reconnaissance, dynamic vulnerability probing, and AST taint analysis in an orchestrated telemetry pipeline.
                  </p>
                  <p>
                    During an audit session, real-time Server-Sent Events (SSE) stream detailed stage logs directly to the user dashboard: from initial DNS/port recon and TLS cipher validation to client bundle JavaScript deobfuscation, Nuclei template probing, Git tree parsing, and automated AI patch generation.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-2">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-blue-400" />
                      <span>Recon Engine</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      DNS records, subdomains, open TCP ports, WAF identification, and TLS handshake analysis.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Nuclei DAST</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Non-destructive active vulnerability probing utilizing 114 curated high-impact templates.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Code2 className="w-3.5 h-3.5 text-purple-400" />
                      <span>AST Taint SAST</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Syntax tree parsing tracing untrusted sources to dangerous sinks across JavaScript, Python, and PHP.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                      <span>AI Remediation</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Proactive git unified diff synthesis providing verified line-by-line vulnerability patches.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {/* Section 2: Audit Execution Modes */}
            {(activeSection === 'modes' || searchQuery) && (
              <section id="modes" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                  <Layers className="w-4 h-4" />
                  <span>PIPELINE ORCHESTRATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Audit Execution Modes
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Configured via the <code className="text-[#ededed] bg-[#111113] px-1 py-0.5 rounded">mode</code> parameter in API requests or the New Audit interface.
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white font-mono">HYBRID (Recommended)</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                        FULL POSTURE AUDIT
                      </span>
                    </div>
                    <p className="text-xs text-[#a1a1aa] font-mono leading-relaxed">
                      Simultaneously executes live external reconnaissance, DAST active probing, and deep whitebox repository scanning. Correlates exposed client-side API endpoints directly with backend controllers and database queries.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white font-mono">BLACKBOX (DAST &amp; Recon)</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                        EXTERNAL TARGETS
                      </span>
                    </div>
                    <p className="text-xs text-[#a1a1aa] font-mono leading-relaxed">
                      Zero-access external testing. Performs DNS enumeration, TCP port scanning, WAF detection, TLS configuration checks, sensitive directory discovery (<code className="text-[#ededed]">.env</code>, <code className="text-[#ededed]">.git</code>, backup archives), and active Nuclei heuristics.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white font-mono">WHITEBOX (SAST Only)</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">
                        SOURCE CODE REPOSITORIES
                      </span>
                    </div>
                    <p className="text-xs text-[#a1a1aa] font-mono leading-relaxed">
                      Static code inspection for public or private Git repositories. Analyzes dependency lockfiles (<code className="text-[#ededed]">package-lock.json</code>, <code className="text-[#ededed]">requirements.txt</code>), unminifies templates, evaluates Shannon entropy on code constants, and performs AST taint analysis.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {/* Section 3: Recon Engine & Attack Surface Mapping */}
            {(activeSection === 'recon' || searchQuery) && (
              <section id="recon" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
                  <Globe className="w-4 h-4" />
                  <span>ATTACK SURFACE RECONNAISSANCE</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Automated Network Recon &amp; Fingerprinting
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Asynchronous pre-audit fingerprinting mapped during the RECON stage (0% – 15%).
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Before firing active vulnerability templates, the <code className="text-[#ededed] bg-[#111113] px-1 py-0.5 rounded">ReconEngine</code> maps the perimeter of target domains using non-intrusive protocols to build an architectural profile:
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">DNS &amp; Subdomain Enumeration</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Resolves A, AAAA, CNAME, MX, and TXT records. Discovers common environment subdomains (<code className="text-[#ededed]">api</code>, <code className="text-[#ededed]">staging</code>, <code className="text-[#ededed]">dev</code>, <code className="text-[#ededed]">admin</code>) and inspects Certificate Transparency (crt.sh) logs.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Async TCP Port Probing</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Probes web services (80, 443, 8080, 8443) and dev/database ports (3306, 5432, 6379, 27017, 9200) with strict connection timeouts to prevent target congestion.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">WAF Fingerprinting</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Identifies Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Cloudfront, ModSecurity, F5 BIG-IP) from response headers, cookies, and TLS behaviors to calibrate rate limits.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">SSL/TLS &amp; Certificate Health</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Validates certificate chain validity, issuer authority, expiration thresholds, and flags weak protocol versions (SSLv3, TLS 1.0, TLS 1.1) and insecure cipher suites.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {/* Section 4: Nuclei DAST Active Probing */}
            {(activeSection === 'nuclei' || searchQuery) && (
              <section id="nuclei" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                  <Zap className="w-4 h-4" />
                  <span>DAST ENGINE SPECIFICATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Nuclei DAST Active Vulnerability Probing
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Curated template matching utilizing the native Nuclei binary engine (v3.3+) with fallback emulation.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    SecAudit incorporates 114 curated, high-precision vulnerability templates stored under <code className="text-[#ededed] bg-[#111113] px-1 py-0.5 rounded">backend/rules/nuclei/</code>. Unlike mass scanners that produce false positives or trigger service disruption, SecAudit applies strict concurrency boundaries, rate limiting, and safe payload validation.
                  </p>
                </div>

                <div className="space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-white font-mono">
                    Supported Scanning Profiles
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-white font-mono">Quick Profile</span>
                        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                          25 Curated Rules
                        </span>
                      </div>
                      <p className="text-[11px] text-[#71717a] font-mono">
                        Fast CVE &amp; critical configuration validation. Executes in ~8–15 seconds with minimal server overhead. Ideal for continuous integration and staging gates.
                      </p>
                    </div>

                    <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-white font-mono">Full Profile</span>
                        <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                          114 Templates
                        </span>
                      </div>
                      <p className="text-[11px] text-[#71717a] font-mono">
                        Comprehensive vulnerability sweep covering exposed administrative actuators, Spring Cloud gateways, blind SSRF, Apache/Nginx CVEs, and CORS misconfigurations.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-white font-mono">CLI Command Verification</div>
                  <CodeSnippet
                    language="bash"
                    code="nuclei -config backend/rules/nuclei/profiles/secaudit-quick.yml -target https://target.app -jsonl"
                  />
                </div>
              </section>
            )}

            {/* Section 5: AST Taint & Source Logic */}
            {(activeSection === 'sast' || searchQuery) && (
              <section id="sast" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
                  <Code2 className="w-4 h-4" />
                  <span>SAST ENGINE SPECIFICATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    AST Taint Tracing &amp; System Logic Analysis
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Tree-sitter and custom AST pattern matchers auditing code structure and variable flow.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Rather than relying solely on naive regex matching, SecAudit parses target source trees into Abstract Syntax Trees. It tracks untrusted input sources (such as <code className="text-[#ededed]">req.body</code>, <code className="text-[#ededed]">$_GET</code>, <code className="text-[#ededed]">request.args</code>) through intermediate transformations to dangerous execution sinks.
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-3">
                  <div className="text-xs font-semibold text-white font-mono">Covered Vulnerability Classes</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono text-[#71717a]">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CWE-79: Cross-Site Scripting (Reflected &amp; DOM)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CWE-89: SQL Injection Sinks</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CWE-1321: Prototype Pollution &amp; Mass Assignment</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CWE-639: Broken Object-Level Auth (BOLA / IDOR)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CWE-434: Unrestricted File Upload Handlers</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Template Injection &amp; Unescaped Directives</span>
                    </div>
                  </div>
                </div>
              </section>
            )}

            {/* Section 6: Shannon Entropy Secret Mining */}
            {(activeSection === 'entropy' || searchQuery) && (
              <section id="entropy" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                  <Lock className="w-4 h-4" />
                  <span>SECRET DETECTION SPECIFICATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Shannon Entropy Secret Mining
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Statistical randomness evaluation combined with regex token prefix classification and strict zero-leak redaction.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Secret tokens (such as AWS Access Keys, OpenAI Keys, Stripe Secrets, and JWT private keys) possess statistically higher character randomness than typical source code identifiers or natural language. SecAudit computes the Shannon Entropy metric:
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] text-center font-mono text-xs text-white">
                  <span>H(X) = - Σ [ P(x_i) · log₂ P(x_i) ]</span>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-2">
                  <p>
                    Tokens that exceed the configurable threshold (default: <code className="text-[#ededed]">4.2 bits/char</code>) are classified against token patterns. When verified, values are masked with non-reversible redaction (<code className="text-rose-400 font-mono">sk-proj-****[REDACTED]</code>) to enforce the Zero Plaintext Secret Retention standard.
                  </p>
                </div>
              </section>
            )}

            {/* Section 7: Authenticated Scanning & Headers */}
            {(activeSection === 'authscan' || searchQuery) && (
              <section id="authscan" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-amber-400">
                  <Key className="w-4 h-4" />
                  <span>AUTHENTICATED AUDITING</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Authenticated Scanning &amp; Custom Headers
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Audit privileged endpoints behind authentication gates, session cookies, and custom Bug Bounty headers.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Modern application flaws frequently reside behind login boundaries. SecAudit allows passing bearer tokens, session cookie strings, and custom header key-values directly to the audit configuration. The scanner securely injects these credentials across external DAST probes, sensitive directory crawlers, and Nuclei HTTP executions.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Bearer Token &amp; API Keys</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Injects <code className="text-[#ededed]">Authorization: Bearer &lt;token&gt;</code> into all outgoing DAST and Nuclei probes to audit authenticated REST and GraphQL APIs.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Session Cookies &amp; Bug Bounty Headers</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Pass raw session cookies (<code className="text-[#ededed]">connect.sid=...; session_id=...</code>) or custom security disclosure headers (e.g., custom User-Agent attribution suffix).
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-white font-mono">API Payload Example</div>
                  <CodeSnippet
                    language="json"
                    code={`{
  "project_name": "Internal Banking Dashboard",
  "mode": "BLACKBOX",
  "target_url": "https://dashboard.internal.bank.com",
  "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "auth_cookie_string": "session_id=s%3A83921...; org_scope=corp",
  "enable_nuclei": true
}`}
                  />
                </div>
              </section>
            )}

            {/* Section 8: Supabase Cloud & Hybrid Persistence */}
            {(activeSection === 'database' || searchQuery) && (
              <section id="database" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                  <Database className="w-4 h-4" />
                  <span>CLOUD &amp; LOCAL HYBRID STORAGE</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Supabase Cloud Database &amp; SQLite Fallback
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Dual-write persistence architecture providing cross-device synchronization with zero data loss guarantee.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    SecAudit utilizes a hybrid persistence architecture combining Supabase PostgREST cloud storage with local SQLite (<code className="text-[#ededed]">aiosqlite</code>). Audit sessions and Quick Presets are written to both engines in parallel. When users query audits, records from Supabase and SQLite are merged by <code className="text-[#ededed]">session_id</code>.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Multi-Device Sync</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Audits and custom presets saved on one workstation automatically sync to any other browser when logged in.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Offline-First Resiliency</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      If Supabase is unreachable or network connectivity drops, all scans continue saving locally into SQLite without interruption.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Session Consolidation</div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Deduplication logic links anonymous scans to newly registered accounts seamlessly upon user login.
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-white font-mono">Supabase SQL Schema Initialization</div>
                  <CodeSnippet
                    language="sql"
                    code={`-- Run in Supabase SQL Editor
CREATE TABLE IF NOT EXISTS presets (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    project_name TEXT NOT NULL,
    mode TEXT NOT NULL,
    url TEXT,
    repo TEXT,
    branch TEXT DEFAULT 'main',
    is_demo BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_presets_user_id ON presets (user_id);
ALTER TABLE presets DISABLE ROW LEVEL SECURITY;`}
                  />
                </div>
              </section>
            )}

            {/* Section 9: Engine Tuning & Heuristics */}
            {(activeSection === 'tuning' || searchQuery) && (
              <section id="tuning" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                  <Cpu className="w-4 h-4" />
                  <span>CONFIGURATION HEURISTICS</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Engine Tuning &amp; Heuristic Thresholds
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Fine-tune scanner aggressiveness, entropy thresholds, and crawling depths.
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Scan Depth (`scan_depth`)</div>
                    <ul className="text-xs font-mono text-[#71717a] space-y-1.5 list-disc pl-5">
                      <li><strong className="text-[#ededed]">Fast (Shallow):</strong> Top 20 TCP ports, primary sensitive paths, 2 client JS bundles. Max ~25 seconds.</li>
                      <li><strong className="text-[#ededed]">Balanced (Medium):</strong> Standard web service ports, comprehensive sensitive directories, 5 client JS bundles. Default setting.</li>
                      <li><strong className="text-[#ededed]">Deep:</strong> Full port sweep (including dev &amp; database ports: 3306, 5432, 6379, 8080, 8443), recursive sub-chunk JS extraction, full source tree AST traversal.</li>
                    </ul>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">Shannon Entropy Threshold (`entropy_threshold`)</div>
                    <p className="text-xs font-mono text-[#71717a]">
                      Valid range: <code className="text-[#ededed]">1.0</code> to <code className="text-[#ededed]">8.0</code>. Recommended: <code className="text-[#ededed]">4.2</code> for high-precision secret mining with zero false positives on natural language strings.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {/* Section 10: REST API & Telemetry Reference */}
            {(activeSection === 'api' || searchQuery) && (
              <section id="api" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
                  <Terminal className="w-4 h-4" />
                  <span>PROGRAMMATIC INTEGRATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    REST API &amp; Server-Sent Events (SSE) Reference
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Integrate SecAudit into CI/CD pipelines, automated PR checks, and external SIEMs.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3 pt-1 pb-2">
                  <a
                    href="/api/docs"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium bg-[#111113] border border-[#1e1e22] text-[#ededed] hover:text-white hover:border-[#3f3f46] transition-colors"
                  >
                    <span>Interactive Swagger UI</span>
                    <ExternalLink className="w-3 h-3 text-[#71717a]" />
                  </a>
                  <a
                    href="/api/redoc"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium bg-[#111113] border border-[#1e1e22] text-[#ededed] hover:text-white hover:border-[#3f3f46] transition-colors"
                  >
                    <span>ReDoc Specification</span>
                    <ExternalLink className="w-3 h-3 text-[#71717a]" />
                  </a>
                  <a
                    href="/api/openapi.json"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium bg-[#111113] border border-[#1e1e22] text-[#ededed] hover:text-white hover:border-[#3f3f46] transition-colors"
                  >
                    <span>Raw OpenAPI JSON</span>
                    <ExternalLink className="w-3 h-3 text-[#71717a]" />
                  </a>
                </div>

                <div className="space-y-6">
                  {/* Endpoint 1: POST /api/v1/audits */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                        POST
                      </span>
                      <code className="text-xs font-mono text-white">/api/v1/audits</code>
                      <span className="text-xs font-mono text-[#71717a]">— Initiate a new security audit</span>
                    </div>
                    <CodeSnippet
                      language="bash"
                      code={`curl -X POST "http://localhost:8000/api/v1/audits" \\
  -H "Content-Type: application/json" \\
  -d '{
    "project_name": "Fintech Core Gateway",
    "mode": "HYBRID",
    "target_url": "https://demo-fintech.auraglass.io",
    "github_repo_url": "https://github.com/auraglass/fintech-dashboard-api",
    "branch": "main",
    "scan_depth": "Medium",
    "entropy_threshold": 4.2,
    "enable_nuclei": true,
    "nuclei_profile": "quick"
  }'`}
                    />
                  </div>

                  {/* Endpoint 2: GET /api/v1/audits/{session_id}/events */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                        GET
                      </span>
                      <code className="text-xs font-mono text-white">/api/v1/audits/{`{session_id}`}/events</code>
                      <span className="text-xs font-mono text-[#71717a]">— Real-time SSE stage telemetry</span>
                    </div>
                    <CodeSnippet
                      language="bash"
                      code={`curl -N "http://localhost:8000/api/v1/audits/922bc74c-5a95-4955-a1fe-fa1461875d49/events"`}
                    />
                  </div>

                  {/* Endpoint 3: GET /api/v1/audits/{session_id} */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                        GET
                      </span>
                      <code className="text-xs font-mono text-white">/api/v1/audits/{`{session_id}`}</code>
                      <span className="text-xs font-mono text-[#71717a]">— Fetch JSON executive report</span>
                    </div>
                    <CodeSnippet
                      language="bash"
                      code={`curl -s "http://localhost:8000/api/v1/audits/922bc74c-5a95-4955-a1fe-fa1461875d49" | jq .score`}
                    />
                  </div>

                  {/* Endpoint 4: GET /api/v1/presets & POST /api/v1/presets */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">
                        GET/POST
                      </span>
                      <code className="text-xs font-mono text-white">/api/v1/presets</code>
                      <span className="text-xs font-mono text-[#71717a]">— Manage persistent cloud presets</span>
                    </div>
                    <CodeSnippet
                      language="bash"
                      code={`# Fetch user presets
curl -s "http://localhost:8000/api/v1/presets" -H "Authorization: Bearer <token>"

# Save a new custom preset
curl -X POST "http://localhost:8000/api/v1/presets" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <token>" \\
  -d '{"project_name": "Staging API", "mode": "HYBRID", "url": "https://staging.app", "repo": "https://github.com/org/repo"}'`}
                    />
                  </div>
                </div>
              </section>
            )}

            {/* Section 11: Docker & CLI Deployment */}
            {(activeSection === 'docker' || searchQuery) && (
              <section id="docker" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                  <Server className="w-4 h-4" />
                  <span>CONTAINER &amp; HOST DEPLOYMENT</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Docker &amp; CLI Deployment
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Multi-service containerized deployment bundling Node.js 20, Python 3.11, and the Nuclei engine.
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">1. Local Multi-Service Development</div>
                    <CodeSnippet
                      language="bash"
                      code={`# Start backend Uvicorn daemon
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# In a separate terminal, launch the Vite development server
npm --prefix frontend run dev`}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-white font-mono">2. Unified Docker Compose Deployment</div>
                    <CodeSnippet
                      language="bash"
                      code={`# Build and launch single-container unified service (Port 8000)
docker compose up --build -d

# Check real-time service health
curl -f http://localhost:8000/api/v1/health`}
                    />
                  </div>
                </div>
              </section>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default DocsPage;
