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
    { id: 'nuclei', title: 'Nuclei DAST Active Probing', icon: Zap },
    { id: 'sast', title: 'AST Taint & Source Logic', icon: Code2 },
    { id: 'entropy', title: 'Shannon Entropy Secret Mining', icon: Lock },
    { id: 'tuning', title: 'Engine Tuning & Heuristics', icon: Cpu },
    { id: 'api', title: 'REST API & Telemetry Reference', icon: Terminal },
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
                  Geist Security Documentation
                </h1>
                <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  v1.4.0
                </span>
              </div>
              <p className="text-xs text-[#71717a] font-mono">
                Technical reference, engine specifications, REST API schemas, and deployment guidelines.
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
                placeholder="Search topics (e.g. nuclei, api, entropy)..."
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
                <span>Runtime Metrics</span>
              </div>
              <div className="space-y-1.5 text-[11px] text-[#71717a]">
                <div className="flex justify-between">
                  <span>Engine Binary:</span>
                  <span className="text-white">Nuclei v3.11</span>
                </div>
                <div className="flex justify-between">
                  <span>Curated Templates:</span>
                  <span className="text-white">114 Rules</span>
                </div>
                <div className="flex justify-between">
                  <span>Inference SAST:</span>
                  <span className="text-white">Gemini Flash Lite</span>
                </div>
                <div className="flex justify-between">
                  <span>Data Retention:</span>
                  <span className="text-emerald-400">0 Days (RAM Only)</span>
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
                    Autonomous Web &amp; Code Security Auditing
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Dual-pipeline posture analysis uniting external DAST probing with whitebox AST taint tracing.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Geist Security (SecAudit) is an enterprise-grade autonomous security auditing platform designed to audit web applications and code repositories before adversaries strike. Traditional scanners separate runtime DAST and static SAST into disconnected silos. Geist bridges both using an orchestrated dual-pipeline telemetry architecture.
                  </p>
                  <p>
                    During an audit, live network probing (TLS handshake, HTTP headers, sensitive file discovery, client JavaScript deobfuscation, and active Nuclei DAST probing) executes simultaneously with AST parser evaluation and Shannon entropy secret mining across repository trees.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Zero-Lag DAST</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Active protocol handshakes, port probes, and non-destructive Nuclei template executions.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="text-xs font-semibold text-white font-mono flex items-center gap-1.5">
                      <Code2 className="w-3.5 h-3.5 text-purple-400" />
                      <span>AST Taint Tracing</span>
                    </div>
                    <p className="text-[11px] text-[#71717a] font-mono leading-relaxed">
                      Abstract syntax tree traversal inspecting sources, sanitizers, and dangerous execution sinks.
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
                    Configured via the <code className="text-[#ededed] bg-[#111113] px-1 py-0.5 rounded">mode</code> parameter in API requests or the New Audit page.
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
                      Simultaneously analyzes live HTTP/TLS endpoints alongside cloned Git repositories. Correlates exposed endpoints found in client JS bundles directly with backend route controllers in source code.
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white font-mono">BLACKBOX (DAST Only)</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                        EXTERNAL TARGETS
                      </span>
                    </div>
                    <p className="text-xs text-[#a1a1aa] font-mono leading-relaxed">
                      Zero-access reconnaissance. Probes open TCP ports, validates TLS certificates, maps sensitive files (<code className="text-[#ededed]">.env</code>, <code className="text-[#ededed]">.git</code>, backup archives), and runs Nuclei active vulnerability heuristics.
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
                      Inspects public or private Git repositories. Analyzes package manifests (<code className="text-[#ededed]">package.json</code>, <code className="text-[#ededed]">requirements.txt</code>), unminifies templates (Blade, JSX, Jinja), evaluates Shannon entropy on code constants, and traces AST taint paths.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {/* Section 3: Nuclei DAST Active Probing */}
            {(activeSection === 'nuclei' || searchQuery) && (
              <section id="nuclei" className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 sm:p-8 space-y-6">
                <div className="flex items-center gap-2 text-xs font-mono text-amber-400">
                  <Zap className="w-4 h-4" />
                  <span>DAST ENGINE SPECIFICATION</span>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight font-sans">
                    Nuclei DAST Active Vulnerability Probing
                  </h2>
                  <p className="text-xs text-[#a1a1aa] font-mono mt-1">
                    Curated template matching utilizing the native Nuclei binary engine (v3.11.0).
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Geist incorporates 114 curated, high-accuracy vulnerability templates stored under <code className="text-[#ededed] bg-[#111113] px-1 py-0.5 rounded">backend/rules/nuclei/</code>. Unlike unfocused massive scanners that cause DoS disruptions, Geist employs strict rate limiting, non-destructive payloads, and intelligent target fingerprinting.
                  </p>
                </div>

                <div className="space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-white font-mono">
                    Supported Profiles
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
                        Fast CVE &amp; critical configuration validation. Executes in ~8–15 seconds with minimal server overhead. Ideal for CI/CD gating and production targets.
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
                        Deep vulnerability sweep covering exposed administrative actuators, Spring Cloud gateways, blind SSRF, Apache/Nginx CVEs, and CORS misconfigurations.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-white font-mono">CLI Command Verification</div>
                  <CodeSnippet
                    language="bash"
                    code="nuclei -config profiles/secaudit-quick.yml -target https://target.app -jsonl"
                  />
                </div>
              </section>
            )}

            {/* Section 4: AST Taint & Source Logic */}
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
                    Rather than relying solely on naive regex matching, Geist parses target source trees into Abstract Syntax Trees. It tracks untrusted input sources (such as <code className="text-[#ededed]">req.body</code>, <code className="text-[#ededed]">$_GET</code>, <code className="text-[#ededed]">request.args</code>) through intermediate transformations to dangerous execution sinks.
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
                      <span>Blade / Jinja Unescaped Directives ({`{!! $var !!}`})</span>
                    </div>
                  </div>
                </div>
              </section>
            )}

            {/* Section 5: Shannon Entropy Secret Mining */}
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
                    Statistical randomness evaluation combined with regex token prefix classification.
                  </p>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-3">
                  <p>
                    Secret tokens (such as AWS Access Keys, OpenAI Keys, Stripe Secrets, and JWT signing secrets) possess statistically higher character randomness than typical source code identifiers or English prose. Geist calculates the Shannon Entropy metric:
                  </p>
                </div>

                <div className="p-4 rounded-lg bg-[#111113] border border-[#1e1e22] text-center font-mono text-xs text-white">
                  <span>H(X) = - Σ [ P(x_i) · log₂ P(x_i) ]</span>
                </div>

                <div className="text-xs font-mono text-[#a1a1aa] leading-relaxed space-y-2">
                  <p>
                    Strings that exceed the configurable threshold (default: <code className="text-[#ededed]">4.2 bits/char</code>) are inspected against regex token signatures. If confirmed, they are masked into non-reversible redacted tokens (<code className="text-rose-400 font-mono">sk-proj-****[REDACTED]</code>) to enforce the Zero-Data Plaintext Retention rule.
                  </p>
                </div>
              </section>
            )}

            {/* Section 6: Engine Tuning & Heuristics */}
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
                      <li><strong className="text-[#ededed]">Balanced:</strong> Standard web service ports, comprehensive sensitive directories, 5 client JS bundles. Default setting.</li>
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

            {/* Section 7: REST API & Telemetry Reference */}
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
                    Integrate Geist Security into CI/CD pipelines, automated PR checks, and external SIEMs.
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
    "project_name": "Acme Fintech Gateway",
    "mode": "HYBRID",
    "target_url": "https://api.acme.com",
    "github_repo_url": "https://github.com/acme/fintech-gateway",
    "branch": "main",
    "scan_depth": "Deep",
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
                      code={`curl -s "http://localhost:8000/api/v1/audits/922bc74c-5a95-4955-a1fe-fa1461875d49" | jq .posture_score`}
                    />
                  </div>
                </div>
              </section>
            )}

            {/* Section 8: Docker & CLI Deployment */}
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
                    Multi-stage containerized deployment bundling Node.js, Python 3.11, and the Nuclei engine.
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
curl -f http://localhost:8000/health`}
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
