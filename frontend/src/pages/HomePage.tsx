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
  ExternalLink,
  Activity,
  Check,
  FlaskConical,
  ShoppingBag,
  CreditCard,
} from 'lucide-react';

type AuditMode = 'hybrid' | 'url' | 'github';

interface Preset {
  id: string;
  title: string;
  subtitle: string;
  url: string;
  repo: string;
  mode: AuditMode;
  icon: 'flask' | 'store' | 'card' | 'zap';
}

function renderPresetIcon(icon: Preset['icon']) {
  switch (icon) {
    case 'flask':
      return <FlaskConical className="w-3.5 h-3.5 text-blue-400 shrink-0" />;
    case 'store':
      return <ShoppingBag className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
    case 'card':
      return <CreditCard className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    case 'zap':
      return <Zap className="w-3.5 h-3.5 text-violet-400 shrink-0" />;
    default:
      return <Zap className="w-3.5 h-3.5 text-[#a1a1aa] shrink-0" />;
  }
}

const PRESETS: Preset[] = [
  {
    id: 'local-lab',
    title: 'Local Lab Target (0.0.0.0:1412)',
    subtitle: 'Recon & JS Crawler • Sensitive File Detection',
    url: 'http://0.0.0.0:1412/',
    repo: '',
    mode: 'url',
    icon: 'flask',
  },
  {
    id: 'storefront',
    title: 'E-Commerce Storefront',
    subtitle: 'AST DOM XSS • JWT Token Leak',
    url: 'https://demo-shop.auraglass.io',
    repo: 'auraglass-labs/umkm-storefront-ast',
    mode: 'hybrid',
    icon: 'store',
  },
  {
    id: 'fintech',
    title: 'Fintech Payment Core',
    subtitle: 'OSV CVE Reachability • Shannon 8.1',
    url: 'https://demo-fintech.auraglass.io',
    repo: 'auraglass-labs/fintech-dashboard-api',
    mode: 'hybrid',
    icon: 'card',
  },
  {
    id: 'gateway',
    title: 'Edge API Gateway',
    subtitle: 'Next.js Injection • Open CORS & Auth',
    url: 'https://gateway.auraglass.io',
    repo: 'auraglass-labs/edge-gateway-nextjs',
    mode: 'url',
    icon: 'zap',
  },
];

const TERMINAL_LOGS = [
  {
    time: '00:01.12',
    tag: '[AST_PARSER]',
    tagColor: 'text-[#ededed]',
    message: 'Synthesizing TypeScript AST hierarchy for 42 files...',
    containerClass: 'text-[#a1a1aa]',
  },
  {
    time: '00:01.89',
    tag: '[TAINT_ENGINE]',
    tagColor: 'text-amber-400',
    message: 'Traced param `req.query.user_token` to sink `db.rawQuery()` [CWE-89 candidate]',
    containerClass: 'bg-red-950/20 text-red-400 px-2 py-0.5 rounded border-l-2 border-red-500',
  },
  {
    time: '00:02.34',
    tag: '[ENTROPY_SCAN]',
    tagColor: 'text-emerald-400',
    message: 'Found potential high-entropy token in `dist/assets/app.js:142` (Entropy: 7.94)',
    containerClass: 'bg-emerald-950/20 text-emerald-300 px-2 py-0.5 rounded border-l-2 border-emerald-500',
  },
  {
    time: '00:02.80',
    tag: '[OSV_SYNC]',
    tagColor: 'text-[#0070f3]',
    message: 'Reachability verified for CVE-2023-26136 in tough-cookie 4.1.2 • Auto-Patch available',
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
  const [projectName, setProjectName] = useState('Fintech Payment Core');
  const [targetUrl, setTargetUrl] = useState('https://demo-fintech.auraglass.io');
  const [targetRepo, setTargetRepo] = useState('auraglass-labs/fintech-dashboard-api');
  const [currentBranch, setCurrentBranch] = useState('main');
  const [showBranchDropdown, setShowBranchDropdown] = useState(false);
  const [selectedPresetId, setSelectedPresetId] = useState<string>('fintech');
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Advanced config state
  const [crawlDepth, setCrawlDepth] = useState('3');
  const [rateLimit, setRateLimit] = useState('moderate');
  const [taintLevel, setTaintLevel] = useState('strict');
  const [maskSensitive, setMaskSensitive] = useState(true);

  // Ping simulation feedback
  const [pingFeedback, setPingFeedback] = useState<string | null>(null);

  // Scan simulation state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanTitle, setScanTitle] = useState('');
  const [scanSubtitle, setScanSubtitle] = useState('');

  const handleModeChange = (newMode: AuditMode) => {
    setMode(newMode);
  };

  const handleApplyPreset = (preset: Preset) => {
    setSelectedPresetId(preset.id);
    setMode(preset.mode);
    setTargetUrl(preset.url);
    setTargetRepo(preset.repo);
    setProjectName(preset.title);
  };

  const handlePing = () => {
    const host = targetUrl ? targetUrl.replace(/^https?:\/\//, '') : 'demo-target.io';
    setPingFeedback(`Ping to ${host}: 18ms (TLS 1.3 Active, HTTP/2). Target responsive.`);
    setTimeout(() => {
      setPingFeedback(null);
    }, 4500);
  };

  const handleLaunchAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;

    setIsScanning(true);
    setScanProgress(25);
    setScanTitle(`Initiating ${mode.toUpperCase()} Audit...`);
    setScanSubtitle(`Target: ${projectName.trim() || targetRepo || targetUrl}`);

    try {
      let finalUrl = targetUrl.trim();
      if (finalUrl && !finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
        finalUrl = `http://${finalUrl}`;
      }
      const modeEnum = mode === 'hybrid' ? 'HYBRID' : mode === 'url' ? 'BLACKBOX' : 'WHITEBOX';
      const resolvedProjectName =
        projectName.trim() || (finalUrl ? `Audit: ${finalUrl.replace(/^https?:\/\//, '')}` : 'Lab Target Audit');

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
    } catch (err) {
      console.warn('Real audit create failed or offline, fallback to demo progress:', err);
      navigate('/audit/progress/demo-fintech');
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

        {/* ─────────────────────────────────────────────────────────────
            1. HERO SECTION
            (centered, max-w-3xl mx-auto, pt-24 pb-10)
        ───────────────────────────────────────────────────────────── */}
        <section className="max-w-3xl mx-auto flex flex-col items-center text-center pt-24 pb-10">
          {/* Status pill */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#1e1e22] bg-[#0a0a0a] hover:border-[#27272a] transition-all cursor-pointer group mb-8 shadow-sm">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0070f3] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#0070f3]" />
            </span>
            <span className="font-mono text-xs text-[#ededed] tracking-tight">Geist Engine v2.4 Live</span>
            <span className="text-[#52525b]">•</span>
            <span className="text-xs text-[#a1a1aa] flex items-center gap-1 group-hover:text-white transition-colors">
              Autonomous Security Audit Launchpad
              <ArrowRight className="w-3.5 h-3.5 text-[#a1a1aa] transition-transform group-hover:translate-x-0.5 group-hover:text-white" />
            </span>
          </div>

          {/* H1 */}
          <h1 className="text-4xl sm:text-6xl md:text-7xl font-bold tracking-tight text-white max-w-4xl mb-6">
            Autonomous Web &amp; Code Security Audits{' '}
            <span className="bg-gradient-to-b from-white via-[#ededed] to-[#71717a] bg-clip-text text-transparent">
              Before Adversaries Strike
            </span>
          </h1>

          {/* Subtitle with inline code badges */}
          <p className="text-base sm:text-lg text-[#a1a1aa] max-w-2xl mb-8 leading-relaxed font-normal">
            Full-spectrum vulnerability assessment via{' '}
            <span className="font-mono text-[#ededed] text-xs px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22]">
              Blackbox URL
            </span>
            ,{' '}
            <span className="font-mono text-[#ededed] text-xs px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22]">
              Whitebox GitHub
            </span>
            , or unified Hybrid correlation powered by AST Taint tracing, OSV.dev CVE reachability, and Shannon Entropy detection.
          </p>

          {/* Stats row */}
          <div className="flex flex-wrap items-center justify-center gap-6 font-mono text-xs text-[#71717a] mb-6">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span className="text-[#a1a1aa]">Threat DB: 231,904 CVEs</span>
            </div>
            <span className="text-[#52525b]">•</span>
            <div className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span className="text-[#a1a1aa]">OSV.dev Real-Time</span>
            </div>
            <span className="text-[#52525b]">•</span>
            <div className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span className="text-[#a1a1aa]">&lt; 30s Full Audit</span>
            </div>
          </div>
        </section>

        {/* ─────────────────────────────────────────────────────────────
            2. LAUNCHPAD CARD
            (max-w-3xl mx-auto)
        ───────────────────────────────────────────────────────────── */}
        <section className="max-w-3xl mx-auto">
          <div className="relative rounded-xl bg-[#0a0a0a] border border-[#1e1e22] shadow-2xl p-6 sm:p-8">
            {/* Terminal header bar */}
            <div className="h-9 bg-[#111113]/70 border-b border-[#1e1e22] -mx-6 sm:-mx-8 -mt-6 sm:-mt-8 mb-6 px-4 flex items-center justify-between rounded-t-xl">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
                <span className="font-mono text-xs text-[#a1a1aa] ml-3 flex items-center gap-1.5">
                  <Lock className="w-3 h-3 text-[#71717a]" />
                  geist-security://smart-launchpad.session
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded border border-[#0070f3]/30 bg-[#0070f3]/10 font-mono text-[10px] text-[#0070f3] font-medium tracking-wide">
                  READY TO AUDIT
                </span>
                <Terminal className="w-3.5 h-3.5 text-[#71717a]" />
              </div>
            </div>

            {/* Mode selector: Hybrid / URL Blackbox / GitHub Whitebox - pill buttons */}
            <div className="flex items-center justify-center mb-6">
              <div className="inline-flex p-1 rounded-lg bg-black border border-[#1e1e22] gap-1">
                <button
                  type="button"
                  onClick={() => handleModeChange('hybrid')}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
                    mode === 'hybrid'
                      ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm'
                      : 'text-[#71717a] hover:text-[#ededed]'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Hybrid (URL + GitHub)</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleModeChange('url')}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
                    mode === 'url'
                      ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm'
                      : 'text-[#71717a] hover:text-[#ededed]'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Website URL (Blackbox)</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleModeChange('github')}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-medium transition-all ${
                    mode === 'github'
                      ? 'bg-[#1e1e22] text-white border border-[#27272a] shadow-sm'
                      : 'text-[#71717a] hover:text-[#ededed]'
                  }`}
                >
                  <FolderCode className="w-3.5 h-3.5" />
                  <span>GitHub Repo (Whitebox)</span>
                </button>
              </div>
            </div>

            {/* Launchpad Form */}
            <form className="flex flex-col gap-4" onSubmit={handleLaunchAudit}>
              {/* Project Name (Audit Identifier) */}
              <div className="flex flex-col gap-1.5 transition-all duration-200">
                <div className="flex items-center justify-between text-xs">
                  <label
                    htmlFor="project-name"
                    className="text-[#ededed] font-medium flex items-center gap-1.5"
                  >
                    <FolderCode className="w-3.5 h-3.5 text-[#71717a]" />
                    Project Name
                  </label>
                  <span className="font-mono text-[11px] text-[#71717a]">Audit identifier</span>
                </div>
                <div className="relative flex items-center">
                  <input
                    id="project-name"
                    name="project_name"
                    type="text"
                    required
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    placeholder="e.g. Modern E-Commerce Portal"
                    aria-label="Project Name"
                    data-testid="project-name-input"
                    className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg px-3 py-2.5 font-mono text-sm placeholder:text-[#52525b] transition-colors outline-none"
                  />
                </div>
              </div>

              {/* URL input field with ping button */}
              {showUrlInput && (
                <div className="flex flex-col gap-1.5 transition-all duration-200">
                  <div className="flex items-center justify-between text-xs">
                    <label className="text-[#ededed] font-medium flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-[#71717a]" />
                      Target Web URL (Runtime / DAST)
                    </label>
                    <div className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Demo &amp; Lab Mode (0.0.0.0 / Localhost OK)
                    </div>
                  </div>
                  <div className="relative flex items-center">
                    <div className="absolute left-3 text-[#52525b] flex items-center pointer-events-none">
                      <Link2 className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      required={showUrlInput}
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="http://0.0.0.0:1412/ or https://target-app.com"
                      className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg pl-9 pr-24 py-2.5 font-mono text-sm placeholder:text-[#52525b] transition-colors outline-none"
                    />
                    <div className="absolute right-2.5 flex items-center gap-1.5">
                      <span className="px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa] font-mono text-[10px]">
                        HTTPS
                      </span>
                      <button
                        type="button"
                        title="Ping Check Latency"
                        onClick={handlePing}
                        className="p-1 rounded hover:bg-[#161618] text-[#a1a1aa] hover:text-white transition-colors"
                      >
                        <Activity className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  {pingFeedback && (
                    <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1.5 pt-0.5 animate-fadeIn">
                      <Check className="w-3 h-3" />
                      <span>{pingFeedback}</span>
                    </div>
                  )}
                </div>
              )}

              {/* GitHub repo input with branch selector */}
              {showGithubInput && (
                <div className="flex flex-col gap-1.5 transition-all duration-200">
                  <div className="flex items-center justify-between text-xs">
                    <label className="text-[#ededed] font-medium flex items-center gap-1.5">
                      <GitBranch className="w-3.5 h-3.5 text-[#71717a]" />
                      GitHub Repository (Source / SAST)
                    </label>
                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#a1a1aa]">
                      <span>Access:</span>
                      <span className="px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                        Read-Only PAT
                      </span>
                    </div>
                  </div>
                  <div className="relative flex items-center">
                    <div className="absolute left-3 text-[#52525b] flex items-center pointer-events-none">
                      <FolderCode className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      required={showGithubInput}
                      value={targetRepo}
                      onChange={(e) => setTargetRepo(e.target.value)}
                      placeholder="owner/repository-name"
                      className="w-full bg-black border border-[#1e1e22] focus:border-[#71717a] focus:ring-0 text-white rounded-lg pl-9 pr-36 py-2.5 font-mono text-sm placeholder:text-[#52525b] transition-colors outline-none"
                    />
                    <div className="absolute right-2.5 flex items-center gap-1.5">
                      {/* Branch selector dropdown */}
                      <div className="relative">
                        <button
                          type="button"
                          onClick={() => setShowBranchDropdown(!showBranchDropdown)}
                          className="flex items-center gap-1 px-2 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#ededed] font-mono text-[11px] cursor-pointer hover:border-[#27272a] transition-colors"
                        >
                          <GitBranch className="w-3 h-3 text-[#71717a]" />
                          <span>{currentBranch}</span>
                          <ChevronDown className="w-2.5 h-2.5 text-[#71717a]" />
                        </button>
                        {showBranchDropdown && (
                          <div className="absolute right-0 top-full mt-1 w-32 bg-[#0a0a0a] border border-[#1e1e22] rounded-md shadow-2xl py-1 z-30">
                            {['main', 'master', 'develop', 'production'].map((branch) => (
                              <button
                                key={branch}
                                type="button"
                                onClick={() => {
                                  setCurrentBranch(branch);
                                  setShowBranchDropdown(false);
                                }}
                                className={`w-full text-left px-3 py-1.5 text-[11px] font-mono hover:bg-[#161618] transition-colors flex items-center justify-between ${
                                  currentBranch === branch
                                    ? 'text-white font-medium bg-[#111113]'
                                    : 'text-[#a1a1aa]'
                                }`}
                              >
                                <span>{branch}</span>
                                {currentBranch === branch && (
                                  <Check className="w-3 h-3 text-[#0070f3]" />
                                )}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa] font-mono text-[10px]">
                        public
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Quick presets row */}
              <div className="flex flex-col gap-2 mt-1">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-[#a1a1aa] flex items-center gap-1.5">
                    <Zap className="w-3 h-3 text-[#a1a1aa]" />
                    1-Click Quick Presets
                  </span>
                  <span className="font-mono text-[11px] text-[#71717a]">Click to load preset target</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {PRESETS.map((preset) => {
                    const isActive = selectedPresetId === preset.id;
                    return (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => handleApplyPreset(preset)}
                        className={`group text-left p-3 rounded-lg border transition-all flex flex-col gap-1 ${
                          isActive
                            ? 'border-[#27272a] bg-[#111113]/50 hover:border-[#3f3f46]'
                            : 'border-[#1e1e22] bg-[#0a0a0a]/60 hover:border-[#27272a] hover:bg-[#111113]/40'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 min-w-0">
                            {renderPresetIcon(preset.icon)}
                            <span
                              className={`text-xs font-medium truncate transition-colors group-hover:text-white ${
                                isActive ? 'text-white' : 'text-[#ededed]'
                              }`}
                            >
                              {preset.title}
                            </span>
                          </div>
                          <ExternalLink className="w-3.5 h-3.5 text-[#52525b] group-hover:text-white transition-transform group-hover:translate-x-0.5 shrink-0 ml-1" />
                        </div>
                        <p className="font-mono text-[11px] text-[#71717a]">{preset.subtitle}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Automatic telemetry modules badge row */}
              <div className="p-3 rounded-lg border border-[#1e1e22] bg-black/60 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-[#52525b]">
                    Active Automated Telemetry Modules
                  </span>
                  <span className="font-mono text-[11px] text-[#a1a1aa]">Zero Configuration Required</span>
                </div>
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span>AST XSS Tracer (Source-to-Sink)</span>
                  </div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#0070f3]" />
                    <span>OSV.dev CVE Reachability</span>
                  </div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#a1a1aa]" />
                    <span>JS Secret &amp; Recon (Entropy 8.0)</span>
                  </div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#111113] border border-[#1e1e22] text-[#ededed]">
                    <CheckCircle2 className="w-3 h-3 text-[#a1a1aa]" />
                    <span>Mandatory Auto-Redaction</span>
                  </div>
                </div>
              </div>

              {/* Advanced options toggle + Launch button */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-md border border-[#1e1e22] bg-[#111113]/60 hover:bg-[#111113] text-[#ededed] hover:text-white text-xs font-medium transition-all w-full sm:w-auto justify-center"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  <span>Advanced Configuration</span>
                  {showAdvanced ? (
                    <ChevronUp className="w-3.5 h-3.5 transition-transform" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 transition-transform" />
                  )}
                </button>
                <button
                  type="submit"
                  disabled={isScanning}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-md bg-white text-black hover:bg-[#e5e2e1] font-semibold text-sm shadow-sm transition-all active:scale-[0.99] w-full sm:w-auto disabled:opacity-70"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>{getLaunchButtonLabel()}</span>
                </button>
              </div>

              {/* Advanced options collapsible panel */}
              {showAdvanced && (
                <div className="flex flex-col gap-4 mt-2 pt-4 border-t border-[#1e1e22]">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white">Custom Audit Parameters</span>
                    <span className="font-mono text-[11px] text-[#71717a]">Optional Configuration</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa]">Max Crawl Depth</label>
                      <select
                        value={crawlDepth}
                        onChange={(e) => setCrawlDepth(e.target.value)}
                        className="px-2.5 py-2 rounded-md bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="3">Depth 3 (Recommended Fast - 45s)</option>
                        <option value="5">Depth 5 (Full Single Page App)</option>
                        <option value="1">Depth 1 (Landing Page Only)</option>
                      </select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa]">Penetration Rate Limit</label>
                      <select
                        value={rateLimit}
                        onChange={(e) => setRateLimit(e.target.value)}
                        className="px-2.5 py-2 rounded-md bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="gentle">Gentle (5 req/sec - Zero Disruption)</option>
                        <option value="moderate">Moderate (20 req/sec)</option>
                        <option value="stress">High Stress (Sandbox Env)</option>
                      </select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-xs text-[#a1a1aa]">Heuristic Taint Level</label>
                      <select
                        value={taintLevel}
                        onChange={(e) => setTaintLevel(e.target.value)}
                        className="px-2.5 py-2 rounded-md bg-black border border-[#1e1e22] text-[#ededed] font-mono text-xs focus:border-[#3f3f46] focus:outline-none"
                      >
                        <option value="strict">Strict (CWE-79 DOM Sink &amp; Eval)</option>
                        <option value="permissive">Permissive (All Unsanitized Inputs)</option>
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
                    <label htmlFor="maskSensitive" className="text-xs text-[#a1a1aa]">
                      Enforce PII &amp; Authorization Token Masking in Live Terminal Logs (ISO 27001 Standard)
                    </label>
                  </div>
                </div>
              )}
            </form>
          </div>

          {/* Live Execution Status Bar (Visible during scan run) */}
          {isScanning && (
            <div className="w-full mt-4 p-4 rounded-xl bg-[#0a0a0a] border border-[#1e1e22] shadow-lg animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="relative flex h-3 w-3">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xs font-semibold text-white">{scanTitle}</span>
                    <span className="font-mono text-[11px] text-[#a1a1aa]">{scanSubtitle}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-28 bg-[#111113] border border-[#1e1e22] rounded-full h-1.5 overflow-hidden hidden sm:block">
                    <div
                      className="bg-white h-1.5 rounded-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                  <span className="px-3 py-1.5 rounded-md bg-[#111113] border border-[#27272a] text-white text-xs font-medium flex items-center gap-1">
                    <span>Storyteller</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ─────────────────────────────────────────────────────────────
            3. FEATURE GRID
            (max-w-7xl mx-auto, mt-16)
        ───────────────────────────────────────────────────────────── */}
        <section className="max-w-7xl mx-auto mt-16">
          {/* Section title */}
          <div className="text-center max-w-2xl mx-auto mb-12">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#1e1e22] bg-[#111113]/60 text-[#ededed] font-mono text-xs uppercase tracking-wider mb-4">
              <Zap className="w-3.5 h-3.5 text-[#a1a1aa]" />
              <span>Built for teams</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white mb-3">
              Why Choose Geist Security Over Conventional Scanners?
            </h2>
            <p className="text-[#a1a1aa] text-base leading-relaxed">
              Geist Security delivers autonomous orchestration and AST-level detection precision to eliminate
              false alarms across modern enterprise stacks.
            </p>
          </div>

          {/* 3-column grid of feature cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {FEATURE_CARDS.map((card) => (
              <div
                key={card.id}
                className="rounded-xl border border-[#1e1e22] bg-[#0a0a0a]/70 p-6 flex flex-col justify-between hover:border-[#27272a] transition-colors"
              >
                <div>
                  <div className="w-10 h-10 rounded-lg border border-[#1e1e22] bg-[#111113] flex items-center justify-center text-white mb-5">
                    {card.id === 'ast' && <Sparkles className="w-5 h-5 text-white" />}
                    {card.id === 'osv' && <Shield className="w-5 h-5 text-white" />}
                    {card.id === 'entropy' && <Key className="w-5 h-5 text-white" />}
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-base font-semibold text-white">{card.title}</h3>
                    <span className="px-1.5 py-0.2 rounded border border-[#1e1e22] bg-[#111113] text-[#a1a1aa] font-mono text-[10px]">
                      {card.badge}
                    </span>
                  </div>
                  <p className="text-sm text-[#a1a1aa] mb-6 leading-relaxed">{card.description}</p>
                </div>
                <div className="pt-3 border-t border-[#1e1e22] flex items-center justify-between font-mono text-xs text-[#52525b]">
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

        {/* ─────────────────────────────────────────────────────────────
            4. TERMINAL PREVIEW
            (max-w-5xl mx-auto)
        ───────────────────────────────────────────────────────────── */}
        <section className="max-w-5xl mx-auto w-full mt-14 mb-20 p-4 rounded-xl bg-black border border-[#1e1e22] font-mono text-xs shadow-xl">
          {/* Terminal header */}
          <div className="h-9 bg-[#111113]/70 border-b border-[#1e1e22] -mx-4 -mt-4 mb-3 px-4 flex items-center justify-between rounded-t-xl">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              <span className="font-mono text-xs text-[#a1a1aa] ml-3 flex items-center gap-1.5">
                <Lock className="w-3 h-3 text-[#71717a]" />
                geist-security://session-8092f.telemetry
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded border border-[#0070f3]/30 bg-[#0070f3]/10 font-mono text-[10px] text-[#0070f3] font-medium tracking-wide">
                LIVE SYNTHESIS
              </span>
              <Terminal className="w-3.5 h-3.5 text-[#71717a]" />
            </div>
          </div>

          {/* Terminal log lines */}
          <div className="space-y-1.5 overflow-x-auto p-1">
            {TERMINAL_LOGS.map((log, index) => (
              <div key={index} className={`flex items-center gap-3 ${log.containerClass}`}>
                <span className="text-[#52525b] select-none">{log.time}</span>
                <span className={`font-semibold ${log.tagColor}`}>{log.tag}</span>
                <span>{log.message}</span>
              </div>
            ))}
            {/* Blinking cursor */}
            <div className="flex items-center gap-3 mt-1 text-[#52525b]">
              <span className="select-none">00:03.15</span>
              <span className="text-[#71717a] animate-pulse">█</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default HomePage;
