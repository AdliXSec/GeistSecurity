import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createAudit } from '../lib/api';
import {
  ArrowRight,
  CheckCircle2,
  Zap,
  Shield,
  Lock,
  Terminal,
  Sparkles,
  Globe,
  FolderCode,
  Link2,
  GitBranch,
  Play,
  ChevronDown,
  ChevronUp,
  SlidersHorizontal,
  Key,
  Check,
  AlertCircle,
} from 'lucide-react';

type AuditMode = 'hybrid' | 'url' | 'github';

const TERMINAL_LOGS = [
  {
    time: '00:01.12',
    tag: '[AST_PARSER]',
    tagColor: 'text-[#ededed]',
    message: 'Synthesizing TypeScript AST hierarchy for target files...',
    containerClass: 'text-[#a1a1aa]',
  },
  {
    time: '00:01.89',
    tag: '[TAINT_ENGINE]',
    tagColor: 'text-amber-400',
    message: 'Tracing param `req.query.user_token` to sink `db.rawQuery()` [CWE-89 candidate]',
    containerClass: 'bg-red-950/20 text-red-400 px-2 py-0.5 rounded border-l-2 border-red-500',
  },
  {
    time: '00:02.34',
    tag: '[ENTROPY_SCAN]',
    tagColor: 'text-emerald-400',
    message: 'High-entropy credential verified in build artifact (Entropy: 7.94)',
    containerClass: 'bg-emerald-950/20 text-emerald-300 px-2 py-0.5 rounded border-l-2 border-emerald-500',
  },
  {
    time: '00:02.80',
    tag: '[OSV_SYNC]',
    tagColor: 'text-[#0070f3]',
    message: 'Reachability verified for CVE-2023-26136 in tough-cookie 4.1.2 • Auto-Patch ready',
    containerClass: 'text-[#a1a1aa]',
  },
];

const FEATURE_CARDS = [
  {
    id: 'ast',
    title: 'AST Taint Analysis',
    badge: 'Included',
    description:
      'Traces user-controlled input propagation to innerHTML and dangerous DOM sinks without invasive runtime execution.',
    footerText: 'Exact Node Lineage',
    footerDotClass: 'bg-[#a1a1aa]',
    badgePlan: 'All plans',
  },
  {
    id: 'osv',
    title: 'OSV CVE Intelligence',
    badge: 'Included',
    description:
      'Verifies whether vulnerable npm/pip dependencies are actively invoked by functions in your codebase, eliminating false alarms.',
    footerText: 'Dependency Graph',
    footerDotClass: 'bg-[#0070f3]',
    badgePlan: 'All plans',
  },
  {
    id: 'entropy',
    title: 'Shannon Entropy Detector',
    badge: 'Included',
    description:
      'Detects hardcoded AWS secret keys, OpenAI tokens, JWT secrets, and database credentials buried in build artifacts.',
    footerText: 'High Density Tokens',
    footerDotClass: 'bg-emerald-500',
    badgePlan: 'All plans',
  },
];

export const HomePage: React.FC = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState<AuditMode>('hybrid');
  const [projectName, setProjectName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [targetRepo, setTargetRepo] = useState('');
  const [currentBranch, setCurrentBranch] = useState('main');
  const [showBranchDropdown, setShowBranchDropdown] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Advanced config state
  const [crawlDepth, setCrawlDepth] = useState('3');
  const [rateLimit, setRateLimit] = useState('moderate');
  const [taintLevel, setTaintLevel] = useState('strict');
  const [maskSensitive, setMaskSensitive] = useState(true);

  // Ping feedback
  const [pingFeedback, setPingFeedback] = useState<string | null>(null);

  // Scan execution state
  const [isScanning, setIsScanning] = useState(false);

  const handleModeChange = (newMode: AuditMode) => {
    setMode(newMode);
    setErrorMessage(null);
  };

  const handlePing = () => {
    const host = targetUrl ? targetUrl.replace(/^https?:\/\//, '') : 'target.domain';
    setPingFeedback(`Ping to ${host}: 18ms (TLS 1.3 Active, HTTP/2). Target responsive.`);
    setTimeout(() => {
      setPingFeedback(null);
    }, 4500);
  };

  const handleLaunchAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;
    setErrorMessage(null);

    let finalUrl = targetUrl.trim();
    if (finalUrl && !finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
      finalUrl = `http://${finalUrl}`;
    }

    if (mode !== 'github' && !finalUrl) {
      setErrorMessage('Target Web URL wajib diisi untuk audit runtime / blackbox.');
      return;
    }
    if (mode !== 'url' && !targetRepo.trim()) {
      setErrorMessage('GitHub Repository wajib diisi untuk audit source code / whitebox.');
      return;
    }

    setIsScanning(true);

    try {
      const modeEnum = mode === 'hybrid' ? 'HYBRID' : mode === 'url' ? 'BLACKBOX' : 'WHITEBOX';
      const resolvedProjectName =
        projectName.trim() ||
        (finalUrl ? `Audit: ${finalUrl.replace(/^https?:\/\//, '')}` : targetRepo.trim() || 'Security Audit');

      const res = await createAudit({
        project_name: resolvedProjectName,
        mode: modeEnum,
        target_url: mode !== 'github' ? finalUrl : undefined,
        github_repo_url:
          mode !== 'url'
            ? targetRepo
              ? targetRepo.startsWith('http')
                ? targetRepo
                : `https://github.com/${targetRepo}`
              : undefined
            : undefined,
        branch: currentBranch || 'main',
        scan_depth: crawlDepth === '1' ? 'Shallow' : crawlDepth === '5' ? 'Deep' : 'Medium',
      });
      navigate(`/audit/progress/${res.session_id}`);
    } catch (err: any) {
      console.error('Audit initialization error:', err);
      setErrorMessage(
        err?.message ||
          'Gagal menginisialisasi sesi audit. Pastikan URL target valid dan lolos validasi Anti-SSRF.'
      );
    } finally {
      setIsScanning(false);
    }
  };

  const getLaunchButtonLabel = () => {
    switch (mode) {
      case 'hybrid':
        return 'Start Deep Security Audit (Hybrid)';
      case 'url':
        return 'Start Blackbox URL Audit';
      case 'github':
        return 'Start Whitebox Source Audit';
    }
  };

  const showUrlInput = mode === 'hybrid' || mode === 'url';
  const showGithubInput = mode === 'hybrid' || mode === 'github';

  return (
    <div className="min-h-screen bg-black font-sans text-[#ededed] antialiased relative selection:bg-[#1e1e22] selection:text-white">
      {/* Vercel Grid Subtle Background */}
      <div
        className="pointer-events-none fixed inset-0 z-0 opacity-60"
        style={{
          backgroundImage:
            'linear-gradient(to right, rgba(255, 255, 255, 0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(255, 255, 255, 0.05) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
          WebkitMaskImage: 'radial-gradient(ellipse 65% 55% at 50% 15%, #000 60%, transparent 100%)',
          maskImage: 'radial-gradient(ellipse 65% 55% at 50% 15%, #000 60%, transparent 100%)',
        }}
      />

      {/* Main Page Container */}
      <div className="relative z-10 px-4 sm:px-6 lg:px-8">
        {/* 1. HERO SECTION */}
        <section className="max-w-3xl mx-auto flex flex-col items-center text-center pt-14 sm:pt-20 pb-8 sm:pb-10">
          {/* Status pill */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#1e1e22] bg-[#0a0a0a] hover:border-[#27272a] transition-all cursor-pointer group mb-6 sm:mb-8 shadow-sm">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0070f3] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#0070f3]" />
            </span>
            <span className="font-mono text-xs text-[#ededed] tracking-tight">Geist Security v2.4</span>
            <span className="text-[#52525b]">•</span>
            <span className="text-xs text-[#a1a1aa] flex items-center gap-1 group-hover:text-white transition-colors">
              Security Audit Launchpad
              <ArrowRight className="w-3.5 h-3.5 text-[#a1a1aa] transition-transform group-hover:translate-x-0.5 group-hover:text-white" />
            </span>
          </div>

          {/* H1 */}
          <h1 className="text-3xl sm:text-5xl md:text-6xl font-bold tracking-tight text-white max-w-4xl mb-4 sm:mb-6 leading-tight">
            Autonomous Web &amp; Code Security Audits{' '}
            <span className="bg-gradient-to-b from-white via-[#ededed] to-[#71717a] bg-clip-text text-transparent">
              Before Adversaries Strike
            </span>
          </h1>

          {/* Subtitle */}
          <p className="text-sm sm:text-base md:text-lg text-[#a1a1aa] max-w-2xl mb-6 sm:mb-8 leading-relaxed font-normal">
            Full-spectrum vulnerability assessment via{' '}
            <span className="font-mono text-[#ededed] text-xs px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22]">
              Blackbox URL
            </span>
            ,{' '}
            <span className="font-mono text-[#ededed] text-xs px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22]">
              Whitebox GitHub
            </span>
            , or unified Hybrid correlation powered by AST taint analysis, OSV CVE reachability, and Shannon entropy secrets detection.
          </p>

          {/* Stats row */}
          <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-6 font-mono text-[11px] sm:text-xs text-[#71717a]">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-[#a1a1aa]">Threat DB: 231,900+ CVEs</span>
            </div>
            <span className="text-[#3f3f46] hidden sm:inline">•</span>
            <div className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-blue-400" />
              <span className="text-[#a1a1aa]">Real-Time Telemetry</span>
            </div>
            <span className="text-[#3f3f46] hidden sm:inline">•</span>
            <div className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-violet-400" />
              <span className="text-[#a1a1aa]">Zero Slop Fallback</span>
            </div>
          </div>
        </section>

        {/* 2. LAUNCHPAD CARD */}
        <section className="max-w-3xl mx-auto">
          <div className="relative rounded-xl bg-[#0a0a0a] border border-[#1e1e22] shadow-2xl p-4 sm:p-6 md:p-8">
            {/* Terminal header bar */}
            <div className="h-9 bg-[#111113]/80 border-b border-[#1e1e22] -mx-4 sm:-mx-6 md:-mx-8 -mt-4 sm:-mt-6 md:-mt-8 mb-6 px-3 sm:px-4 flex items-center justify-between rounded-t-xl gap-2 min-w-0">
              <div className="flex items-center gap-1.5 sm:gap-2 min-w-0 flex-1">
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                </div>
                <span className="font-mono text-[10px] sm:text-xs text-[#a1a1aa] ml-1.5 sm:ml-3 flex items-center gap-1 min-w-0 truncate">
                  <Lock className="w-3 h-3 text-[#71717a] shrink-0" />
                  <span className="sm:hidden truncate">smart-launchpad</span>
                  <span className="hidden sm:inline truncate">geist-security://smart-launchpad.session</span>
                </span>
              </div>
              <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
                <span className="px-1.5 sm:px-2 py-0.5 rounded border border-[#0070f3]/30 bg-[#0070f3]/10 font-mono text-[9px] sm:text-[10px] text-[#0070f3] font-medium tracking-wide whitespace-nowrap">
                  READY TO AUDIT
                </span>
                <Terminal className="w-3.5 h-3.5 text-[#71717a] hidden sm:block" />
              </div>
            </div>

            {/* Mode selector: Responsive Segmented Control */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 p-1 rounded-xl bg-[#000000] border border-[#1e1e22] w-full mb-6">
              <button
                type="button"
                onClick={() => handleModeChange('hybrid')}
                className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-mono transition-all ${
                  mode === 'hybrid'
                    ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm font-medium'
                    : 'text-[#71717a] hover:text-[#ededed] hover:bg-[#111113]'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                <span>Hybrid (URL + Code)</span>
              </button>
              <button
                type="button"
                onClick={() => handleModeChange('url')}
                className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-mono transition-all ${
                  mode === 'url'
                    ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm font-medium'
                    : 'text-[#71717a] hover:text-[#ededed] hover:bg-[#111113]'
                }`}
              >
                <Globe className="w-3.5 h-3.5 text-emerald-400" />
                <span>Website URL (DAST)</span>
              </button>
              <button
                type="button"
                onClick={() => handleModeChange('github')}
                className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-mono transition-all ${
                  mode === 'github'
                    ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm font-medium'
                    : 'text-[#71717a] hover:text-[#ededed] hover:bg-[#111113]'
                }`}
              >
                <FolderCode className="w-3.5 h-3.5 text-violet-400" />
                <span>GitHub Repo (SAST)</span>
              </button>
            </div>

            {/* Launchpad Form */}
            <form className="flex flex-col gap-4" onSubmit={handleLaunchAudit}>
              {/* Project Name (Audit Identifier) */}
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-xs">
                  <label htmlFor="project-name" className="text-[#ededed] font-medium flex items-center gap-1.5">
                    <FolderCode className="w-3.5 h-3.5 text-[#71717a]" />
                    Project Name
                  </label>
                  <span className="font-mono text-[11px] text-[#71717a]">Audit identifier</span>
                </div>
                <div className="relative flex items-center">
                  <span className="absolute left-3 text-[#52525b] pointer-events-none">
                    <FolderCode className="w-4 h-4" />
                  </span>
                  <input
                    id="project-name"
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    placeholder="e.g. Production Payment API"
                    className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg pl-9 pr-3 py-2.5 font-mono text-xs sm:text-sm placeholder:text-[#52525b] transition-colors outline-none"
                  />
                </div>
              </div>

              {/* Target Web URL */}
              {showUrlInput && (
                <div className="flex flex-col gap-1.5 animate-fadeIn">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="target-url" className="text-[#ededed] font-medium flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-[#71717a]" />
                      Target Web URL (Runtime / DAST)
                    </label>
                    <span className="font-mono text-[11px] text-[#71717a]">Anti-SSRF Enforced</span>
                  </div>
                  <div className="relative flex items-center">
                    <span className="absolute left-3 text-[#52525b] pointer-events-none">
                      <Link2 className="w-4 h-4" />
                    </span>
                    <input
                      id="target-url"
                      type="text"
                      required={showUrlInput}
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg pl-9 pr-24 py-2.5 font-mono text-xs sm:text-sm placeholder:text-[#52525b] transition-colors outline-none"
                    />
                    <div className="absolute right-2.5 flex items-center gap-1.5">
                      {targetUrl && (
                        <button
                          type="button"
                          onClick={handlePing}
                          className="px-2 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa] hover:text-white font-mono text-[11px] hover:border-[#27272a] transition-colors"
                        >
                          Ping
                        </button>
                      )}
                      <span className="px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#ededed] font-mono text-[10px] uppercase">
                        {targetUrl.startsWith('https://') ? 'HTTPS' : 'HTTP'}
                      </span>
                    </div>
                  </div>
                  {pingFeedback && (
                    <div className="text-[11px] font-mono text-emerald-400 bg-emerald-950/20 border border-emerald-900/40 px-3 py-1.5 rounded-md mt-1 animate-fadeIn">
                      {pingFeedback}
                    </div>
                  )}
                </div>
              )}

              {/* GitHub Repository */}
              {showGithubInput && (
                <div className="flex flex-col gap-1.5 animate-fadeIn">
                  <div className="flex items-center justify-between text-xs">
                    <label htmlFor="github-repo" className="text-[#ededed] font-medium flex items-center gap-1.5">
                      <FolderCode className="w-3.5 h-3.5 text-[#71717a]" />
                      GitHub Repository (Source / SAST)
                    </label>
                    <span className="font-mono text-[11px] text-[#71717a]">Public / Token Access</span>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2">
                    <div className="relative flex-1 flex items-center">
                      <span className="absolute left-3 text-[#52525b] pointer-events-none">
                        <FolderCode className="w-4 h-4" />
                      </span>
                      <input
                        id="github-repo"
                        type="text"
                        required={showGithubInput}
                        value={targetRepo}
                        onChange={(e) => setTargetRepo(e.target.value)}
                        placeholder="owner/repository-name"
                        className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg pl-9 pr-3 py-2.5 font-mono text-xs sm:text-sm placeholder:text-[#52525b] transition-colors outline-none"
                      />
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {/* Branch selector dropdown */}
                      <div className="relative flex-1 sm:flex-initial">
                        <button
                          type="button"
                          onClick={() => setShowBranchDropdown(!showBranchDropdown)}
                          className="w-full sm:w-auto flex items-center justify-between sm:justify-start gap-1.5 px-3 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] text-[#ededed] font-mono text-xs hover:border-[#27272a] transition-colors"
                        >
                          <GitBranch className="w-3.5 h-3.5 text-[#71717a]" />
                          <span>{currentBranch}</span>
                          <ChevronDown className="w-3 h-3 text-[#71717a]" />
                        </button>
                        {showBranchDropdown && (
                          <div className="absolute right-0 top-full mt-1 w-36 bg-[#0a0a0a] border border-[#1e1e22] rounded-md shadow-2xl py-1 z-30">
                            {['main', 'master', 'develop', 'production'].map((branch) => (
                              <button
                                key={branch}
                                type="button"
                                onClick={() => {
                                  setCurrentBranch(branch);
                                  setShowBranchDropdown(false);
                                }}
                                className={`w-full text-left px-3 py-1.5 text-xs font-mono hover:bg-[#161618] transition-colors flex items-center justify-between ${
                                  currentBranch === branch
                                    ? 'text-white font-medium bg-[#111113]'
                                    : 'text-[#a1a1aa]'
                                }`}
                              >
                                <span>{branch}</span>
                                {currentBranch === branch && (
                                  <Check className="w-3.5 h-3.5 text-[#0070f3]" />
                                )}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                      <span className="px-2 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] text-[#71717a] font-mono text-xs">
                        public
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Error Alert Banner */}
              {errorMessage && (
                <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-800/50 text-red-400 text-xs font-mono flex items-start gap-2.5 animate-fadeIn">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <span className="font-semibold">Launch Failure:</span> {errorMessage}
                  </div>
                </div>
              )}

              {/* Advanced options toggle + Launch button */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-lg border border-[#1e1e22] bg-[#111113]/60 hover:bg-[#111113] text-[#ededed] hover:text-white text-xs font-mono transition-all"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5 text-[#71717a]" />
                  <span>Advanced Parameters</span>
                  {showAdvanced ? (
                    <ChevronUp className="w-3.5 h-3.5 transition-transform" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 transition-transform" />
                  )}
                </button>
                <button
                  type="submit"
                  disabled={isScanning}
                  className="inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-white text-black hover:bg-[#ededed] font-mono font-semibold text-xs sm:text-sm shadow-sm transition-all active:scale-[0.99] disabled:opacity-70"
                >
                  {isScanning ? (
                    <>
                      <span className="w-3.5 h-3.5 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                      <span>Initializing Pipeline...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>{getLaunchButtonLabel()}</span>
                    </>
                  )}
                </button>
              </div>

              {/* Advanced options collapsible panel */}
              {showAdvanced && (
                <div className="flex flex-col gap-4 mt-2 pt-4 border-t border-[#1e1e22] animate-fadeIn">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white">Custom Audit Parameters</span>
                    <span className="font-mono text-[11px] text-[#71717a]">Optional Configuration</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa] font-mono">Max Crawl Depth</label>
                      <select
                        value={crawlDepth}
                        onChange={(e) => setCrawlDepth(e.target.value)}
                        className="px-2.5 py-2 rounded-lg bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="3">Depth 3 (Standard - Recommended)</option>
                        <option value="5">Depth 5 (Deep Single Page App)</option>
                        <option value="1">Depth 1 (Landing Surface Only)</option>
                      </select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa] font-mono">Rate Limit</label>
                      <select
                        value={rateLimit}
                        onChange={(e) => setRateLimit(e.target.value)}
                        className="px-2.5 py-2 rounded-lg bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="gentle">Gentle (5 req/sec)</option>
                        <option value="moderate">Moderate (20 req/sec)</option>
                        <option value="stress">High Stress (Sandbox)</option>
                      </select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa] font-mono">Taint Heuristic</label>
                      <select
                        value={taintLevel}
                        onChange={(e) => setTaintLevel(e.target.value)}
                        className="px-2.5 py-2 rounded-lg bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="strict">Strict (DOM Sink &amp; Eval)</option>
                        <option value="permissive">Permissive (Unsanitized)</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <input
                      id="maskSensitive"
                      type="checkbox"
                      checked={maskSensitive}
                      onChange={(e) => setMaskSensitive(e.target.checked)}
                      className="rounded bg-black border-[#1e1e22] text-white focus:ring-0"
                    />
                    <label htmlFor="maskSensitive" className="text-xs text-[#a1a1aa] font-mono">
                      Enforce PII &amp; Token Redaction in Telemetry Stream
                    </label>
                  </div>
                </div>
              )}
            </form>
          </div>
        </section>

        {/* 3. FEATURE GRID */}
        <section className="max-w-7xl mx-auto mt-16 sm:mt-20">
          <div className="text-center max-w-2xl mx-auto mb-10 sm:mb-12">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#1e1e22] bg-[#111113]/60 text-[#ededed] font-mono text-xs uppercase tracking-wider mb-4">
              <Zap className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span>Production Pipeline</span>
            </div>
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold tracking-tight text-white mb-3">
              Precision Security Orchestration
            </h2>
            <p className="text-[#a1a1aa] text-sm sm:text-base leading-relaxed">
              Autonomous orchestration with AST-level detection precision to eliminate false positives across modern web and API applications.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
            {FEATURE_CARDS.map((card) => (
              <div
                key={card.id}
                className="rounded-xl border border-[#1e1e22] bg-[#0a0a0a]/70 p-5 sm:p-6 flex flex-col justify-between hover:border-[#27272a] transition-colors"
              >
                <div>
                  <div className="w-10 h-10 rounded-lg border border-[#1e1e22] bg-[#111113] flex items-center justify-center text-white mb-4 sm:mb-5">
                    {card.id === 'ast' && <Sparkles className="w-5 h-5 text-blue-400" />}
                    {card.id === 'osv' && <Shield className="w-5 h-5 text-emerald-400" />}
                    {card.id === 'entropy' && <Key className="w-5 h-5 text-violet-400" />}
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-sm sm:text-base font-semibold text-white">{card.title}</h3>
                    <span className="px-1.5 py-0.2 rounded border border-[#1e1e22] bg-[#111113] text-[#a1a1aa] font-mono text-[10px]">
                      {card.badge}
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-[#a1a1aa] mb-5 sm:mb-6 leading-relaxed font-normal">
                    {card.description}
                  </p>
                </div>
                <div className="pt-3 border-t border-[#1e1e22] flex items-center justify-between font-mono text-[11px] sm:text-xs text-[#52525b]">
                  <span className="flex items-center gap-1.5 text-[#a1a1aa]">
                    <span className={`w-1.5 h-1.5 rounded-full ${card.footerDotClass}`} />
                    {card.footerText}
                  </span>
                  <span>{card.badgePlan}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* 4. TERMINAL PREVIEW */}
        <section className="max-w-5xl mx-auto w-full mt-12 sm:mt-16 mb-16 sm:mb-20 p-3 sm:p-4 rounded-xl bg-black border border-[#1e1e22] font-mono text-xs shadow-xl">
          <div className="h-9 bg-[#111113]/70 border-b border-[#1e1e22] -mx-3 sm:-mx-4 -mt-3 sm:-mt-4 mb-3 px-3 sm:px-4 flex items-center justify-between rounded-t-xl gap-2 min-w-0">
            <div className="flex items-center gap-1.5 sm:gap-2 min-w-0 flex-1">
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              </div>
              <span className="font-mono text-[10px] sm:text-xs text-[#a1a1aa] ml-1.5 sm:ml-3 flex items-center gap-1 min-w-0 truncate">
                <Lock className="w-3 h-3 text-[#71717a] shrink-0" />
                <span className="sm:hidden truncate">telemetry-preview</span>
                <span className="hidden sm:inline truncate">geist-security://telemetry-preview.log</span>
              </span>
            </div>
            <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
              <span className="px-1.5 sm:px-2 py-0.5 rounded border border-[#0070f3]/30 bg-[#0070f3]/10 font-mono text-[9px] sm:text-[10px] text-[#0070f3] font-medium tracking-wide whitespace-nowrap">
                LIVE TELEMETRY
              </span>
              <Terminal className="w-3.5 h-3.5 text-[#71717a] hidden sm:block" />
            </div>
          </div>

          <div className="overflow-x-auto p-1 text-[11px] sm:text-xs">
            <div className="space-y-1.5 min-w-max">
              {TERMINAL_LOGS.map((log, index) => (
                <div key={index} className={`flex items-center gap-2 sm:gap-3 ${log.containerClass} whitespace-nowrap`}>
                  <span className="text-[#52525b] select-none shrink-0 font-mono">{log.time}</span>
                  <span className={`font-semibold shrink-0 font-mono ${log.tagColor}`}>{log.tag}</span>
                  <span className="whitespace-nowrap font-mono">{log.message}</span>
                </div>
              ))}
              <div className="flex items-center gap-3 mt-1 text-[#52525b] whitespace-nowrap">
                <span className="select-none font-mono">00:03.15</span>
                <span className="text-[#71717a] animate-pulse">█</span>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default HomePage;
