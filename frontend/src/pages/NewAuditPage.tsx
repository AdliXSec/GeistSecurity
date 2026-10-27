import { useState, type FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { createAudit, type AuditMode } from '../lib/api';

interface Preset {
  id: string;
  projectName: string;
  url: string;
  repo: string;
  branch: string;
  mode: AuditMode;
}

const PRESETS: Preset[] = [
  {
    id: 'local-lab',
    projectName: 'Local Lab Target (0.0.0.0:1412)',
    url: 'http://0.0.0.0:1412/',
    repo: '',
    branch: 'main',
    mode: 'BLACKBOX',
  },
  {
    id: 'ecommerce',
    projectName: 'Modern E-Commerce Portal',
    url: 'https://demo-shop.dev',
    repo: 'https://github.com/company/ecommerce-web',
    branch: 'main',
    mode: 'HYBRID',
  },
  {
    id: 'fintech',
    projectName: 'Fintech Payment Gateway',
    url: 'https://demo-fintech.auraglass.io',
    repo: 'https://github.com/auraglass/fintech-dashboard-api',
    branch: 'main',
    mode: 'HYBRID',
  },
  {
    id: 'edge',
    projectName: 'Edge Gateway Blackbox',
    url: 'https://edge.secure-gateway.io',
    repo: '',
    branch: 'main',
    mode: 'BLACKBOX',
  },
  {
    id: 'auth-repo',
    projectName: 'Auth Service SAST',
    url: '',
    repo: 'https://github.com/acme-corp/auth-core',
    branch: 'main',
    mode: 'WHITEBOX',
  },
];

export default function NewAuditPage() {
  const navigate = useNavigate();

  const [projectName, setProjectName] = useState('Modern E-Commerce Portal');
  const [mode, setMode] = useState<AuditMode>('HYBRID');
  const [websiteUrl, setWebsiteUrl] = useState('https://demo-shop.dev');
  const [repoUrl, setRepoUrl] = useState('https://github.com/company/ecommerce-web');
  const [branch, setBranch] = useState('main');

  // Advanced options state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [jsExposure, setJsExposure] = useState(true);
  const [entropyThreshold, setEntropyThreshold] = useState(4.2);
  const [scanDepth, setScanDepth] = useState<'Shallow' | 'Medium' | 'Deep'>('Medium');
  const [enableNuclei, setEnableNuclei] = useState(true);
  const [nucleiProfile, setNucleiProfile] = useState<'quick' | 'full'>('quick');

  // Submission state
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const applyPreset = (preset: Preset) => {
    setProjectName(preset.projectName);
    setMode(preset.mode);
    setWebsiteUrl(preset.url);
    setRepoUrl(preset.repo);
    setBranch(preset.branch);
    setErrorMessage(null);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    try {
      let finalUrl = websiteUrl.trim();
      if (finalUrl && !finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
        finalUrl = `http://${finalUrl}`;
      }

      const res = await createAudit({
        project_name: projectName,
        mode,
        target_url: mode !== 'WHITEBOX' ? finalUrl : undefined,
        github_repo_url: mode !== 'BLACKBOX' ? repoUrl : undefined,
        branch,
        entropy_threshold: entropyThreshold,
        scan_depth: scanDepth as 'Shallow' | 'Medium' | 'Deep',
        js_exposure: jsExposure,
        enable_nuclei: enableNuclei,
        nuclei_profile: nucleiProfile,
      });

      // Navigate to progress page with the real returned session_id
      navigate(`/audit/progress/${res.session_id}`);
    } catch (err: any) {
      console.error('Audit initialization error:', err);
      // Fallback for offline demo if backend is offline
      setErrorMessage(err.message || 'Failed to initiate audit. Verify backend service connection.');
      setIsLoading(false);
    }
  };

  return (
    <div className="py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl mx-auto w-full space-y-6">
        {/* Breadcrumb: PROJECTS / NEW AUDIT */}
        <div className="text-xs font-mono text-[#71717a] uppercase flex items-center gap-2">
          <Link to="/dashboard" className="hover:text-white transition-colors">
            PROJECTS
          </Link>
          <span className="text-[#3f3f46]">/</span>
          <span className="text-[#e5e2e1] font-semibold">NEW AUDIT</span>
        </div>

        {/* H1: New Security Audit */}
        <div className="space-y-1">
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            New Security Audit
          </h1>
          <p className="text-sm text-[#71717a]">
            Autonomous whitebox AST taint analysis, dependency CVE scanning &amp; blackbox DAST hardening.
          </p>
        </div>

        {/* Quick Presets Section */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-[#71717a] uppercase tracking-wider">Quick Presets</span>
            <span className="text-[#52525b]">1-Click Preload</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => applyPreset(p)}
                className="px-3 py-1.5 rounded-lg text-xs font-mono bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#d4d4d8] hover:text-white transition-all flex items-center gap-1.5"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span>{p.projectName}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Error Alert Banner */}
        {errorMessage && (
          <div className="p-3.5 bg-red-950/40 border border-red-800/60 rounded-xl text-xs font-mono text-red-400 flex items-start gap-2.5">
            <svg className="w-4 h-4 text-red-400 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <div className="space-y-1 flex-1">
              <span className="font-semibold block text-red-300">Audit Initialization Failed</span>
              <p className="text-red-400/90 font-sans leading-relaxed">{errorMessage}</p>
            </div>
            <button
              type="button"
              onClick={() => {
                // Allow fallback demo run if user clicks continue
                navigate('/audit/progress/demo-fintech');
              }}
              className="text-[11px] underline hover:text-white whitespace-nowrap"
            >
              Continue in Demo Mode →
            </button>
          </div>
        )}

        {/* Form Card: bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 */}
        <form
          onSubmit={handleSubmit}
          className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 space-y-6 shadow-2xl"
        >
          {/* Project Name (PRD Required Field) */}
          <div className="space-y-1.5">
            <label
              htmlFor="project-name"
              className="block text-xs font-mono uppercase tracking-wider text-[#a1a1aa]"
            >
              Project Name
            </label>
            <input
              id="project-name"
              name="project_name"
              aria-label="Project Name"
              data-testid="project-name-input"
              type="text"
              required
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="e.g. Modern E-Commerce Portal"
              className="w-full h-9 px-3 bg-[#111113] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder:text-[#52525b] focus:outline-none focus:border-[#71717a] transition-colors"
            />
          </div>

          {/* Mode Selector (3 buttons: Hybrid, URL Blackbox, GitHub Whitebox) */}
          <div className="space-y-2">
            <label className="block text-xs font-mono uppercase tracking-wider text-[#71717a]">
              Audit Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-1 bg-[#111113] border border-[#1e1e22] rounded-lg">
              <button
                type="button"
                onClick={() => setMode('HYBRID')}
                className={`py-2 px-3 rounded-md text-xs font-mono transition-all flex flex-col items-center justify-center gap-0.5 ${
                  mode === 'HYBRID'
                    ? 'bg-white text-black font-semibold shadow-sm'
                    : 'text-[#71717a] hover:text-white'
                }`}
              >
                <span>Hybrid (Recommended)</span>
                <span className="text-[10px] opacity-75 font-sans">AST Whitebox + Live DAST</span>
              </button>

              <button
                type="button"
                onClick={() => setMode('BLACKBOX')}
                className={`py-2 px-3 rounded-md text-xs font-mono transition-all flex flex-col items-center justify-center gap-0.5 ${
                  mode === 'BLACKBOX'
                    ? 'bg-white text-black font-semibold shadow-sm'
                    : 'text-[#71717a] hover:text-white'
                }`}
              >
                <span>Blackbox Recon</span>
                <span className="text-[10px] opacity-75 font-sans">URL Recon &amp; 7 Surface Modules</span>
              </button>

              <button
                type="button"
                onClick={() => setMode('WHITEBOX')}
                className={`py-2 px-3 rounded-md text-xs font-mono transition-all flex flex-col items-center justify-center gap-0.5 ${
                  mode === 'WHITEBOX'
                    ? 'bg-white text-black font-semibold shadow-sm'
                    : 'text-[#71717a] hover:text-white'
                }`}
              >
                <span>Whitebox SAST</span>
                <span className="text-[10px] opacity-75 font-sans">GitHub Repo AST &amp; SCA</span>
              </button>
            </div>
          </div>

          {/* Dynamic Fields based on mode */}
          <div className="space-y-4">
            {/* URL Mode / Hybrid Mode: Website URL */}
            {(mode === 'HYBRID' || mode === 'BLACKBOX') && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="website-url"
                    className="block text-xs font-mono text-[#a1a1aa]"
                  >
                    Target Website URL
                  </label>
                  <span className="text-[10px] font-mono text-emerald-400/90 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Demo &amp; Lab Mode (0.0.0.0 / Localhost OK)
                  </span>
                </div>
                <input
                  id="website-url"
                  type="text"
                  required
                  value={websiteUrl}
                  onChange={(e) => setWebsiteUrl(e.target.value)}
                  placeholder="http://0.0.0.0:1412/ or https://demo-shop.dev"
                  className="w-full h-9 px-3 bg-[#111113] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder:text-[#52525b] focus:outline-none focus:border-[#71717a] transition-colors"
                />
              </div>
            )}

            {/* GitHub Mode / Hybrid Mode: Repo URL + Branch */}
            {(mode === 'HYBRID' || mode === 'WHITEBOX') && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="repo-url"
                      className="block text-xs font-mono text-[#a1a1aa]"
                    >
                      GitHub Repository URL
                    </label>
                    <span className="text-[10px] font-mono text-[#52525b]">Tree-sitter / AST Taint</span>
                  </div>
                  <input
                    id="repo-url"
                    type="text"
                    required
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="w-full h-9 px-3 bg-[#111113] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder:text-[#52525b] focus:outline-none focus:border-[#71717a] transition-colors"
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="branch"
                    className="block text-xs font-mono text-[#a1a1aa]"
                  >
                    Branch
                  </label>
                  <input
                    id="branch"
                    type="text"
                    required
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="main"
                    className="w-full h-9 px-3 bg-[#111113] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder:text-[#52525b] focus:outline-none focus:border-[#71717a] transition-colors"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Advanced Options (Collapsible) */}
          <div className="border-t border-[#1e1e22] pt-4">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center justify-between w-full text-xs font-mono text-[#71717a] hover:text-white transition-colors"
            >
              <span className="flex items-center gap-2">
                <span>Advanced Engine Options</span>
                <span className="px-1.5 py-0.5 rounded bg-[#111113] text-[10px] text-[#52525b]">
                  {mode === 'WHITEBOX' ? 'Entropy & AST Depth' : 'DAST, Entropy & Depth'}
                </span>
              </span>
              <span>{showAdvanced ? '− Hide' : '+ Show'}</span>
            </button>

            {showAdvanced && (
              <div className="mt-4 space-y-4 p-4 rounded-lg bg-[#111113]/50 border border-[#1e1e22]">
                {/* JS Exposure Toggle (Blackbox & Hybrid web chunks only) */}
                {mode !== 'WHITEBOX' && (
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs font-mono text-[#a1a1aa] block">
                        JavaScript Asset Deobfuscation
                      </span>
                      <span className="text-[10px] text-[#52525b] font-sans">
                        Extract hidden API keys, endpoints, and sourcemaps in client chunks
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setJsExposure(!jsExposure)}
                      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        jsExposure ? 'bg-white' : 'bg-[#1e1e22]'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-black shadow ring-0 transition duration-200 ease-in-out ${
                          jsExposure ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                )}

                {/* Entropy Threshold Slider */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <label htmlFor="entropy-slider" className="text-[#a1a1aa]">
                      Shannon Entropy Threshold H(X)
                    </label>
                    <span className="text-white font-semibold">{entropyThreshold.toFixed(1)} / 8.0</span>
                  </div>
                  <input
                    id="entropy-slider"
                    type="range"
                    min="3.0"
                    max="6.0"
                    step="0.1"
                    value={entropyThreshold}
                    onChange={(e) => setEntropyThreshold(parseFloat(e.target.value))}
                    className="w-full accent-white cursor-pointer bg-[#1e1e22] h-1.5 rounded-lg"
                  />
                  <div className="flex justify-between text-[10px] font-mono text-[#52525b]">
                    <span>3.0 (High noise)</span>
                    <span className="text-white font-medium">4.2 (PRD Standard)</span>
                    <span>6.0 (High-randomness only)</span>
                  </div>
                </div>

                {/* Scan Depth Selector */}
                <div className="space-y-1.5">
                  <label
                    htmlFor="scan-depth"
                    className="block text-xs font-mono text-[#a1a1aa]"
                  >
                    Scan Depth
                  </label>
                  <select
                    id="scan-depth"
                    value={scanDepth}
                    onChange={(e) => setScanDepth(e.target.value as any)}
                    className="w-full h-9 px-3 bg-[#0a0a0a] rounded-lg border border-[#1e1e22] text-xs font-mono text-white focus:outline-none focus:border-[#71717a] cursor-pointer"
                  >
                    <option value="Shallow">
                      {mode === 'WHITEBOX' ? 'Shallow — Quick SAST Regex & Dependencies (~10s)' : 'Shallow — Quick Recon & Headers (~10s)'}
                    </option>
                    <option value="Medium">
                      Medium — Full AST + OSV.dev Database (~25s)
                    </option>
                    <option value="Deep">
                      {mode === 'WHITEBOX' ? 'Deep — Deep Taint Analysis & AI Logic Reasoning (~60s)' : 'Deep — Deep Taint Analysis & Sinks (~60s)'}
                    </option>
                  </select>
                </div>

                {/* Nuclei Engine Toggle & Profile (Blackbox & Hybrid live target only) */}
                {mode !== 'WHITEBOX' && (
                  <div className="pt-2 border-t border-[#1e1e22]/60 space-y-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="block text-xs font-mono text-[#ededed]">
                          Nuclei Curated DAST Engine
                        </span>
                        <span className="block text-[11px] font-mono text-[#71717a]">
                          Active scanning via curated templates (DAST, panels, CVEs)
                        </span>
                      </div>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={enableNuclei}
                        onClick={() => setEnableNuclei(!enableNuclei)}
                        className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          enableNuclei ? 'bg-white' : 'bg-[#1e1e22]'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-black shadow ring-0 transition duration-200 ease-in-out ${
                            enableNuclei ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>

                    {enableNuclei && (
                      <div className="space-y-1.5 pl-3 border-l-2 border-[#1e1e22]">
                        <label htmlFor="nuclei-profile" className="block text-xs font-mono text-[#a1a1aa]">
                          Nuclei Template Profile
                        </label>
                        <select
                          id="nuclei-profile"
                          value={nucleiProfile}
                          onChange={(e) => setNucleiProfile(e.target.value as 'quick' | 'full')}
                          className="w-full h-9 px-3 bg-[#0a0a0a] rounded-lg border border-[#1e1e22] text-xs font-mono text-white focus:outline-none focus:border-[#71717a] cursor-pointer"
                        >
                          <option value="quick">Quick Profile — Secrets, Git, Headers &amp; Takeovers (25 templates, ~15-45s)</option>
                          <option value="full">Comprehensive Profile — All Curated (DAST, Panels, CVEs, 114 templates, ~1-3m)</option>
                        </select>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Start Audit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="bg-white text-black hover:bg-[#e5e2e1] w-full h-10 rounded-lg font-medium text-xs font-mono uppercase tracking-wider transition-all flex items-center justify-center gap-2 active:scale-[0.99] disabled:opacity-50"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin h-3.5 w-3.5 text-black" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                <span>Initializing Pipeline...</span>
              </>
            ) : (
              <span>Start Autonomous Audit</span>
            )}
          </button>
        </form>

        {/* Footer info */}
        <div className="flex items-center justify-between text-xs font-mono text-[#52525b] px-1">
          <span>Non-destructive AST testing</span>
          <span>Zero cloud plaintext retention</span>
        </div>
      </div>
    </div>
  );
}
