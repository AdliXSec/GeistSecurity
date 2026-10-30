import { useState, useEffect, type FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  createAudit,
  fetchPresets,
  createPreset,
  deletePresetApi,
  restoreDemoPresetsApi,
  type AuditMode,
} from '../lib/api';

interface Preset {
  id: string;
  projectName: string;
  url: string;
  repo: string;
  branch: string;
  mode: AuditMode;
  isDemo?: boolean;
}

const PRESETS_STORAGE_KEY = 'secaudit_presets_v1';

const DEFAULT_DEMO_PRESET: Preset = {
  id: 'demo-fintech',
  projectName: 'Fintech Payment Gateway (Demo)',
  url: 'https://demo-fintech.auraglass.io',
  repo: 'https://github.com/auraglass/fintech-dashboard-api',
  branch: 'main',
  mode: 'HYBRID',
  isDemo: true,
};

function loadPresets(): Preset[] {
  try {
    const raw = localStorage.getItem(PRESETS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch { /* ignore */ }
  return [DEFAULT_DEMO_PRESET];
}

function persistPresets(list: Preset[]) {
  try {
    localStorage.setItem(PRESETS_STORAGE_KEY, JSON.stringify(list));
  } catch { /* ignore */ }
}

export default function NewAuditPage() {
  const navigate = useNavigate();

  // Preset state (persisted in database + cached in localStorage)
  const [presets, setPresets] = useState<Preset[]>(loadPresets);
  const [isSyncingPresets, setIsSyncingPresets] = useState(false);
  const [showSavePreset, setShowSavePreset] = useState(false);
  const [presetSaveName, setPresetSaveName] = useState('');

  // Fetch presets from database (Supabase Cloud + Local SQLite) on mount
  useEffect(() => {
    let isMounted = true;
    fetchPresets()
      .then((items) => {
        if (isMounted && Array.isArray(items) && items.length > 0) {
          const mapped: Preset[] = items.map((i) => ({
            id: i.id,
            projectName: i.project_name,
            url: i.url || '',
            repo: i.repo || '',
            branch: i.branch || 'main',
            mode: i.mode,
            isDemo: Boolean(i.is_demo),
          }));
          setPresets(mapped);
          persistPresets(mapped);
        }
      })
      .catch((err) => {
        console.warn('Unable to sync presets from cloud DB:', err);
      })
      .finally(() => {
        if (isMounted) setIsSyncingPresets(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const [projectName, setProjectName] = useState('');
  const [mode, setMode] = useState<AuditMode>('HYBRID');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');

  // Advanced options state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [jsExposure, setJsExposure] = useState(true);
  const [entropyThreshold, setEntropyThreshold] = useState(4.2);
  const [scanDepth, setScanDepth] = useState<'Shallow' | 'Medium' | 'Deep'>('Medium');
  const [enableNuclei, setEnableNuclei] = useState(true);
  const [nucleiProfile, setNucleiProfile] = useState<'quick' | 'full'>('quick');

  // Authenticated scanning state
  const [showAuth, setShowAuth] = useState(false);
  const [authToken, setAuthToken] = useState('');
  const [authCookieString, setAuthCookieString] = useState('');

  // Submission state
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const applyPreset = (preset: Preset) => {
    setProjectName(preset.projectName.replace(/\s*\(Demo\)$/i, ''));
    setMode(preset.mode);
    setWebsiteUrl(preset.url);
    setRepoUrl(preset.repo);
    setBranch(preset.branch);
    setErrorMessage(null);
  };

  const handleSavePreset = async () => {
    const name = presetSaveName.trim() || projectName.trim() || 'Custom Preset';
    const tempId = `custom-${Date.now()}`;
    const newPreset: Preset = {
      id: tempId,
      projectName: name,
      url: websiteUrl.trim(),
      repo: repoUrl.trim(),
      branch: branch.trim() || 'main',
      mode,
      isDemo: false,
    };
    
    // Optimistic UI update
    const updated = [...presets, newPreset];
    setPresets(updated);
    persistPresets(updated);
    setShowSavePreset(false);
    setPresetSaveName('');

    // Persist to Cloud Database (Supabase + Local SQLite)
    try {
      const saved = await createPreset({
        project_name: name,
        mode,
        url: websiteUrl.trim(),
        repo: repoUrl.trim(),
        branch: branch.trim() || 'main',
        is_demo: false,
      });
      if (saved && saved.id) {
        setPresets((prev) =>
          prev.map((p) =>
            p.id === tempId ? { ...p, id: saved.id, projectName: saved.project_name } : p
          )
        );
      }
    } catch (err) {
      console.warn('Failed to persist preset to database:', err);
    }
  };

  const handleDeletePreset = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    // Optimistic UI update
    const updated = presets.filter((p) => p.id !== id);
    setPresets(updated);
    persistPresets(updated);

    // Delete from Cloud Database (Supabase + Local SQLite)
    try {
      await deletePresetApi(id);
    } catch (err) {
      console.warn('Failed to delete preset from database:', err);
    }
  };

  const handleRestoreDefault = async () => {
    // Optimistic update
    const updated = [DEFAULT_DEMO_PRESET];
    setPresets(updated);
    persistPresets(updated);

    // Call restore API
    try {
      const restored = await restoreDemoPresetsApi();
      if (Array.isArray(restored) && restored.length > 0) {
        const mapped: Preset[] = restored.map((i) => ({
          id: i.id,
          projectName: i.project_name,
          url: i.url || '',
          repo: i.repo || '',
          branch: i.branch || 'main',
          mode: i.mode,
          isDemo: Boolean(i.is_demo),
        }));
        setPresets(mapped);
        persistPresets(mapped);
      }
    } catch (err) {
      console.warn('Failed to reset demo presets in database:', err);
    }
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
        auth_token: authToken.trim() || undefined,
        auth_cookie_string: authCookieString.trim() || undefined,
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
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-[#71717a] uppercase tracking-wider">Quick Presets</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
                {presets.length} active
              </span>
              {isSyncingPresets && (
                <span className="text-[10px] text-[#71717a] flex items-center gap-1 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  syncing...
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {!showSavePreset ? (
                <button
                  type="button"
                  onClick={() => {
                    setPresetSaveName(projectName || '');
                    setShowSavePreset(true);
                  }}
                  className="text-xs text-white hover:text-emerald-400 transition-colors flex items-center gap-1 font-mono"
                >
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                  <span>Save Current as Preset</span>
                </button>
              ) : null}
              {presets.length === 0 && (
                <button
                  type="button"
                  onClick={handleRestoreDefault}
                  className="text-xs text-[#a1a1aa] hover:text-white underline font-mono"
                >
                  Restore Demo
                </button>
              )}
            </div>
          </div>

          {/* Inline Preset Creator Form */}
          {showSavePreset && (
            <div className="p-3 bg-[#111113] border border-[#1e1e22] rounded-xl space-y-2">
              <div className="flex items-center justify-between text-[11px] font-mono text-[#a1a1aa]">
                <span>Save Current Target Configuration</span>
                <span className="text-[#52525b]">Mode: {mode} · Branch: {branch || 'main'}</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={presetSaveName}
                  onChange={(e) => setPresetSaveName(e.target.value)}
                  placeholder="Nama Preset (mis. Production Auth API / Staging E-Commerce)"
                  className="flex-1 h-8 px-2.5 bg-[#0a0a0a] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder-[#52525b] focus:outline-none focus:border-[#71717a]"
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleSavePreset();
                    } else if (e.key === 'Escape') {
                      setShowSavePreset(false);
                    }
                  }}
                />
                <button
                  type="button"
                  onClick={handleSavePreset}
                  className="h-8 px-3 rounded-lg bg-white text-black hover:bg-[#e5e2e1] text-xs font-mono font-medium transition-all"
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => setShowSavePreset(false)}
                  className="h-8 px-2.5 rounded-lg border border-[#1e1e22] text-[#71717a] hover:text-white text-xs font-mono transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Presets Chips */}
          <div className="flex flex-wrap items-center gap-2">
            {presets.length === 0 ? (
              <div className="text-xs font-mono text-[#52525b] py-1 flex items-center gap-2">
                <span>Belum ada preset tersimpan.</span>
                <button
                  type="button"
                  onClick={handleRestoreDefault}
                  className="text-white underline hover:text-emerald-400"
                >
                  Muat ulang Preset Demo Fintech
                </button>
              </div>
            ) : (
              presets.map((p) => (
                <div
                  key={p.id}
                  onClick={() => applyPreset(p)}
                  role="button"
                  tabIndex={0}
                  className="group px-2.5 py-1.5 rounded-lg text-xs font-mono bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] hover:border-[#27272a] text-[#d4d4d8] hover:text-white transition-all flex items-center gap-2 cursor-pointer select-none"
                  title={`Klik untuk memuat target: ${p.url || p.repo}`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      p.isDemo ? 'bg-emerald-400' : 'bg-cyan-400'
                    }`}
                  />
                  <span>{p.projectName}</span>
                  <span className="text-[10px] px-1 py-0.2 rounded bg-[#1e1e22] text-[#71717a] uppercase font-mono">
                    {p.mode}
                  </span>
                  <button
                    type="button"
                    onClick={(e) => handleDeletePreset(p.id, e)}
                    className="text-[#71717a] hover:text-red-400 hover:bg-[#27272a]/60 rounded p-0.5 ml-0.5 transition-colors"
                    title="Hapus preset ini"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              ))
            )}
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

          {/* Authenticated Scanning & Session Credentials (Blackbox & Hybrid only) */}
          {mode !== 'WHITEBOX' && (
            <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-4 sm:p-5 space-y-4">
              <button
                type="button"
                onClick={() => setShowAuth(!showAuth)}
                className="w-full flex items-center justify-between text-left group"
              >
                <div className="flex items-center gap-2">
                  <svg
                    className={`w-3.5 h-3.5 text-[#71717a] transition-transform duration-200 ${
                      showAuth ? 'rotate-90' : ''
                    }`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono uppercase tracking-wider text-[#a1a1aa] group-hover:text-white transition-colors">
                        Authenticated Scan &amp; Private API Access
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        P1 / IDOR Support
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-[#52525b] block mt-0.5">
                      Suntikkan header / cookie sesi untuk audit endpoint private dan Broken Access Control
                    </span>
                  </div>
                </div>
                <span className="text-[11px] font-mono text-[#71717a] hidden sm:block">
                  {showAuth ? 'Hide Auth Config' : (authToken || authCookieString ? 'Active Credentials' : 'Configure')}
                </span>
              </button>

              {showAuth && (
                <div className="pt-3 border-t border-[#1e1e22] space-y-4">
                  {/* Auth Token / Bearer Header */}
                  <div className="space-y-1.5">
                    <label htmlFor="auth-token" className="block text-xs font-mono text-[#a1a1aa]">
                      Authorization Token / Bearer Key
                    </label>
                    <input
                      id="auth-token"
                      type="text"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="Bearer eyJhbGciOi... atau secret_api_key_xxx"
                      className="w-full h-9 px-3 bg-[#000000] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder-[#52525b] focus:outline-none focus:border-[#71717a]"
                    />
                    <p className="text-[11px] font-mono text-[#52525b]">
                      Otomatis disuntikkan ke HTTP header <code className="text-[#a1a1aa]">Authorization: Bearer &lt;token&gt;</code> untuk seluruh modul recon &amp; Nuclei DAST.
                    </p>
                  </div>

                  {/* Auth Cookie String */}
                  <div className="space-y-1.5">
                    <label htmlFor="auth-cookies" className="block text-xs font-mono text-[#a1a1aa]">
                      Session Cookies (Cookie Header String)
                    </label>
                    <textarea
                      id="auth-cookies"
                      rows={2}
                      value={authCookieString}
                      onChange={(e) => setAuthCookieString(e.target.value)}
                      placeholder="session=a8f9c1...; connect.sid=s%3A...; user_id=102"
                      className="w-full p-2.5 bg-[#000000] rounded-lg border border-[#1e1e22] text-xs font-mono text-white placeholder-[#52525b] focus:outline-none focus:border-[#71717a] resize-none"
                    />
                    <p className="text-[11px] font-mono text-[#52525b]">
                      Format standar <code className="text-[#a1a1aa]">key=value; key2=value2</code> untuk menembus form login wall dan audit endpoint pengguna terotentikasi.
                    </p>
                  </div>

                  {/* Privacy / Zero Plaintext Note */}
                  <div className="p-2.5 rounded-lg bg-[#000000]/60 border border-[#1e1e22] flex items-center gap-2 text-[11px] font-mono text-[#71717a]">
                    <svg className="w-3.5 h-3.5 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    <span>Privasi Pentest: Kredensial aktif di memori scan sesi lokal dan otomatis disensor <code className="text-zinc-300">[REDACTED]</code> sebelum disimpan.</span>
                  </div>
                </div>
              )}
            </div>
          )}

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
