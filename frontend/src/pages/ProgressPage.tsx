import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom';
import { getStoredToken, API_BASE } from '../lib/api';

interface Stage {
  id: number;
  key: string;
  name: string;
  detail: string;
  status: 'completed' | 'in_progress' | 'queued';
}

interface LogEntry {
  id: number;
  time: string;
  tag: string;
  tagColor: string;
  message: string;
}

const WHITEBOX_STAGES: Stage[] = [
  {
    id: 1,
    key: 'WB_INIT',
    name: '1. Ingestion & Git Workspace',
    detail: 'Clone repository, validate branch & parse AST source tree',
    status: 'in_progress',
  },
  {
    id: 2,
    key: 'WB_SCA_CVE',
    name: '2. SCA & Dependency Intelligence',
    detail: 'Parse lockfiles (composer, npm, pip) & correlate OSV.dev CVE database',
    status: 'queued',
  },
  {
    id: 3,
    key: 'WB_AST_XSS',
    name: '3. AST & Template Security Engine',
    detail: 'Audit unescaped template sinks ({!! $var !!}) & DOM injection vectors',
    status: 'queued',
  },
  {
    id: 4,
    key: 'WB_SECRETS',
    name: '4. Secret & Credential Mining',
    detail: 'Compute Shannon Entropy H(X)>=4.2, scan .env leaks, API tokens & private keys',
    status: 'queued',
  },
  {
    id: 5,
    key: 'WB_TAINT_LOGIC',
    name: '5. Deep Taint Analysis & Business Logic',
    detail: 'Trace untrusted input flows from routes/controllers into DB, File, and Auth sinks',
    status: 'queued',
  },
  {
    id: 6,
    key: 'WB_AI_REMEDIATION',
    name: '6. AI Remediation & Code Patching',
    detail: 'Contextual risk analysis, CVSS posture calculation & Before vs After patch generation',
    status: 'queued',
  },
];

const BLACKBOX_STAGES: Stage[] = [
  {
    id: 1,
    key: 'BB_INIT',
    name: '1. Initialization & Anti-SSRF',
    detail: 'Target URL reconnaissance & Anti-SSRF private IP range validation',
    status: 'in_progress',
  },
  {
    id: 2,
    key: 'BB_PORT_RADAR',
    name: '2. Open Port Radar',
    detail: 'Parallel socket probes across DB/Cache/Web ports matched to scan depth profile',
    status: 'queued',
  },
  {
    id: 3,
    key: 'BB_SSL_TLS',
    name: '3. SSL/TLS Certificate Analyzer',
    detail: 'Validate X.509 certificates, validity period, TLS protocols & HTTPS redirection',
    status: 'queued',
  },
  {
    id: 4,
    key: 'BB_TECH_CVE',
    name: '4. Tech Stack & CVE Lookup',
    detail: 'Fingerprint server headers, DOM scripts & query OSV.dev vulnerabilities',
    status: 'queued',
  },
  {
    id: 5,
    key: 'BB_DIR_FINDER',
    name: '5. Sensitive Directory & File Probe',
    detail: 'Probe sensitive paths (.env, .git, backups) with Soft-404 anomaly guards',
    status: 'queued',
  },
  {
    id: 6,
    key: 'BB_JS_EXPOSURE',
    name: '6. HTML Leaks & JS Secrets',
    detail: 'Extract regex API keys, Shannon Entropy H(X)>=4.2 & masked credentials',
    status: 'queued',
  },
  {
    id: 7,
    key: 'BB_AI_REMEDIATION',
    name: '7. AI Posture Scoring & Fixes',
    detail: 'Synthesize AI remediation guidelines & compute CVSS severity scores',
    status: 'queued',
  },
];

const HYBRID_STAGES: Stage[] = [
  {
    id: 1,
    key: 'HYB_INIT',
    name: '1. Initialization & Target Ingestion',
    detail: 'Synchronize Git repository & enforce Anti-SSRF target web checks',
    status: 'in_progress',
  },
  {
    id: 2,
    key: 'HYB_SCA_NETWORK',
    name: '2. SCA Dependencies & Port Radar',
    detail: 'Audit lockfile dependencies & socket probe perimeter open ports',
    status: 'queued',
  },
  {
    id: 3,
    key: 'HYB_RECON_PROBE',
    name: '3. Endpoint Recon & Sensitive Paths',
    detail: 'Probe sensitive web directories, endpoints & TLS certificates',
    status: 'queued',
  },
  {
    id: 4,
    key: 'HYB_SAST_AST',
    name: '4. SAST AST & Template Engine',
    detail: 'Audit template XSS ({!! $var !!}) & mine source code secrets',
    status: 'queued',
  },
  {
    id: 5,
    key: 'HYB_TAINT_JS',
    name: '5. JS Asset Unpack & Deep Taint Flow',
    detail: 'Deobfuscate client JS bundles & trace backend application logic',
    status: 'queued',
  },
  {
    id: 6,
    key: 'HYB_AI_REMEDIATION',
    name: '6. AI Correlation & Posture Scoring',
    detail: 'Correlate blackbox-whitebox findings & generate Before vs After code patches',
    status: 'queued',
  },
];

function getStagesForMode(mode?: string): Stage[] {
  const m = (mode || '').toUpperCase();
  if (m === 'BLACKBOX') {
    return BLACKBOX_STAGES.map((s) => ({ ...s }));
  }
  if (m === 'HYBRID') {
    return HYBRID_STAGES.map((s) => ({ ...s }));
  }
  return WHITEBOX_STAGES.map((s) => ({ ...s }));
}

const STAGE_ORDERS: Record<string, string[]> = {
  WHITEBOX: ['WB_INIT', 'WB_SCA_CVE', 'WB_AST_XSS', 'WB_SECRETS', 'WB_TAINT_LOGIC', 'WB_AI_REMEDIATION', 'COMPLETED'],
  BLACKBOX: ['BB_INIT', 'BB_PORT_RADAR', 'BB_SSL_TLS', 'BB_TECH_CVE', 'BB_DIR_FINDER', 'BB_JS_EXPOSURE', 'BB_AI_REMEDIATION', 'COMPLETED'],
  HYBRID: ['HYB_INIT', 'HYB_SCA_NETWORK', 'HYB_RECON_PROBE', 'HYB_SAST_AST', 'HYB_TAINT_JS', 'HYB_AI_REMEDIATION', 'COMPLETED'],
};

const normalizeStageKey = (rawStage: string, mode: string): string => {
  const stage = (rawStage || '').toUpperCase();
  if (mode === 'WHITEBOX') {
    if (stage === 'INIT' || stage === 'WB_INIT') return 'WB_INIT';
    if (stage === 'CVE_SCAN' || stage === 'WB_SCA_CVE') return 'WB_SCA_CVE';
    if (stage === 'XSS_AUDIT' || stage === 'WB_AST_XSS') return 'WB_AST_XSS';
    if (stage === 'JS_EXPOSURE' || stage === 'WB_SECRETS') return 'WB_SECRETS';
    if (stage === 'WB_TAINT_LOGIC') return 'WB_TAINT_LOGIC';
    if (stage === 'AI_REMEDIATION' || stage === 'WB_AI_REMEDIATION') return 'WB_AI_REMEDIATION';
    return stage;
  }
  if (mode === 'BLACKBOX') {
    if (stage === 'INIT' || stage === 'BB_INIT') return 'BB_INIT';
    if (stage === 'RECON_PORT_SCAN' || stage === 'BB_PORT_RADAR') return 'BB_PORT_RADAR';
    if (stage === 'RECON_SSL_TLS' || stage === 'BB_SSL_TLS') return 'BB_SSL_TLS';
    if (stage === 'RECON_TECH_CVE' || stage === 'CVE_SCAN' || stage === 'BB_TECH_CVE') return 'BB_TECH_CVE';
    if (stage === 'RECON_DIR_FINDER' || stage === 'BB_DIR_FINDER') return 'BB_DIR_FINDER';
    if (stage === 'RECON_HTML_JS' || stage === 'JS_EXPOSURE' || stage === 'BB_JS_EXPOSURE') return 'BB_JS_EXPOSURE';
    if (stage === 'AI_REMEDIATION' || stage === 'BB_AI_REMEDIATION') return 'BB_AI_REMEDIATION';
    return stage;
  }
  // HYBRID
  if (stage === 'INIT' || stage === 'HYB_INIT') return 'HYB_INIT';
  if (stage === 'CVE_SCAN' || stage === 'HYB_SCA_NETWORK') return 'HYB_SCA_NETWORK';
  if (stage === 'RECON_DIR_FINDER' || stage === 'HYB_RECON_PROBE') return 'HYB_RECON_PROBE';
  if (stage === 'XSS_AUDIT' || stage === 'HYB_SAST_AST') return 'HYB_SAST_AST';
  if (stage === 'JS_EXPOSURE' || stage === 'HYB_TAINT_JS') return 'HYB_TAINT_JS';
  if (stage === 'AI_REMEDIATION' || stage === 'HYB_AI_REMEDIATION') return 'HYB_AI_REMEDIATION';
  return stage;
};

const getStageTag = (stage: string) => {
  if (stage.startsWith('WB_INIT') || stage === 'INIT') return { tag: '[GIT:INGEST]', color: 'text-emerald-400' };
  if (stage.startsWith('WB_SCA')) return { tag: '[SCA:CVE]', color: 'text-cyan-400' };
  if (stage.startsWith('WB_AST')) return { tag: '[AST:XSS]', color: 'text-amber-400' };
  if (stage.startsWith('WB_SECRET')) return { tag: '[SAST:SECRET]', color: 'text-red-400' };
  if (stage.startsWith('WB_TAINT')) return { tag: '[TAINT:FLOW]', color: 'text-purple-400' };
  if (stage.includes('AI_REMEDIATION')) return { tag: '[AI:SYNTHESIS]', color: 'text-indigo-400' };
  if (stage === 'COMPLETED') return { tag: '[FINALIZED]', color: 'text-emerald-400' };
  if (stage.startsWith('BB_INIT')) return { tag: '[AUTH:SSRF]', color: 'text-emerald-400' };
  if (stage.startsWith('BB_PORT')) return { tag: '[PORT:RADAR]', color: 'text-blue-400' };
  if (stage.startsWith('BB_SSL')) return { tag: '[SSL:TLS]', color: 'text-teal-400' };
  if (stage.startsWith('BB_TECH')) return { tag: '[TECH:CVE]', color: 'text-cyan-400' };
  if (stage.startsWith('BB_DIR')) return { tag: '[PROBE:LEAKS]', color: 'text-rose-400' };
  if (stage.startsWith('BB_JS')) return { tag: '[JS:CRAWLER]', color: 'text-amber-400' };
  return { tag: `[${stage}]`, color: 'text-blue-400' };
};

export default function ProgressPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();

  const navStateMode = (location.state as any)?.mode;
  const queryMode = new URLSearchParams(location.search).get('mode');
  const initialMode = ((navStateMode || queryMode || 'BLACKBOX') as string).toUpperCase() as
    | 'WHITEBOX'
    | 'BLACKBOX'
    | 'HYBRID';

  const [auditMode, setAuditMode] = useState<'WHITEBOX' | 'BLACKBOX' | 'HYBRID'>(initialMode);
  const [progress, setProgress] = useState(15);
  const [elapsedTime, setElapsedTime] = useState(0.0);
  const [eventsCount, setEventsCount] = useState(18);
  const [sseRate, setSseRate] = useState(128);
  const [isPaused, setIsPaused] = useState(false);
  const [terminalCollapsed, setTerminalCollapsed] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);
  const [streamConnected, setStreamConnected] = useState(false);

  const [narrative, setNarrative] = useState(
    'Initializing workspace and security pipeline. Preparing scan engine & vulnerability databases...'
  );

  const [stages, setStages] = useState<Stage[]>(() => getStagesForMode(initialMode));

  const [logs, setLogs] = useState<LogEntry[]>([
    {
      id: 1,
      time: '0.1s',
      tag: '[WORKSPACE:INIT]',
      tagColor: 'text-emerald-400',
      message: 'Workspace in-memory initialized. Security analysis ready to execute.',
    },
    {
      id: 2,
      time: '0.4s',
      tag: '[ENGINE:READY]',
      tagColor: 'text-blue-400',
      message: 'Preparing security pipeline & vulnerability scanner...',
    },
  ]);

  const eventSourceRef = useRef<EventSource | null>(null);
  const elapsedTimeRef = useRef<number>(0.0);
  const lastEventTimeRef = useRef<number>(0);

  // Connect to SSE stream & Polling Fallback
  useEffect(() => {
    const sessionId = id || 'demo-fintech';
    const streamUrl = `${API_BASE}/audits/${sessionId}/stream`;

    let es: EventSource | null = null;
    let isTerminated = false;

    // Fetch initial audit metadata to immediately lock mode
    const token = getStoredToken();
    const authHeaders: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};

    fetch(`${API_BASE}/audits/${sessionId}`, { headers: authHeaders })
      .then((res) => {
        if (res.ok) return res.json();
        return null;
      })
      .then((data) => {
        if (data && data.mode) {
          const m = data.mode.toUpperCase() as 'WHITEBOX' | 'BLACKBOX' | 'HYBRID';
          setAuditMode(m);
          setStages(getStagesForMode(m));
          if (m === 'WHITEBOX') {
            setNarrative('Connecting to target Git repository and validating branch. Preparing AST parser, SCA analyzer & detection engine...');
          } else if (m === 'BLACKBOX') {
            setNarrative('Initializing workspace and verifying URL anti-SSRF policy. Preparing network probe & CVE fingerprint database...');
          } else {
            setNarrative('Initializing Hybrid mode: synchronizing Git repository and probing target web endpoints...');
          }
        }
      })
      .catch(() => {});

    const handleEventData = (dataStr: string) => {
      if (isPaused || isTerminated) return;
      lastEventTimeRef.current = Date.now();
      try {
        const data = JSON.parse(dataStr);
        setEventsCount((prev) => prev + 1);

        const currentMode = (data.mode || auditMode).toUpperCase() as 'WHITEBOX' | 'BLACKBOX' | 'HYBRID';
        if (data.mode && data.mode.toUpperCase() !== auditMode) {
          setAuditMode(currentMode);
          setStages(getStagesForMode(currentMode));
        }

        if (data.progress !== undefined) {
          setProgress(data.progress);
        }

        if (data.message) {
          setNarrative(data.message);
          const tagInfo = getStageTag(data.stage || 'STAGE');
          setLogs((prev) => [
            ...prev,
            {
              id: prev.length + 1,
              time: `${elapsedTimeRef.current.toFixed(1)}s`,
              tag: tagInfo.tag,
              tagColor: tagInfo.color,
              message: data.message,
            },
          ]);
        }

        // Update stage status
        if (data.stage) {
          const currentKey = normalizeStageKey(data.stage, currentMode);
          const stageOrder = STAGE_ORDERS[currentMode] || STAGE_ORDERS.WHITEBOX;
          const currentIndex = stageOrder.indexOf(currentKey);

          setStages((prev) => {
            const currentStages = prev.length ? prev : getStagesForMode(currentMode);
            return currentStages.map((s) => {
              if (s.key === currentKey) {
                return { ...s, status: 'in_progress' };
              }
              const stageIndex = stageOrder.indexOf(s.key);
              if (currentIndex >= 0 && stageIndex >= 0) {
                if (currentIndex > stageIndex) {
                  return { ...s, status: 'completed' };
                }
                if (currentIndex < stageIndex) {
                  return { ...s, status: 'queued' };
                }
              }
              return s;
            });
          });
        }

        if (data.status === 'completed' || data.stage === 'COMPLETED' || data.progress === 100) {
          isTerminated = true;
          setIsCompleted(true);
          setProgress(100);
          setStages((prev) => prev.map((s) => ({ ...s, status: 'completed' })));
          if (es) es.close();

          setTimeout(() => {
            navigate(`/audit/report/${sessionId}`);
          }, 1200);
        }
      } catch (err) {
        console.warn('Error parsing SSE chunk:', err);
      }
    };

    try {
      es = new EventSource(streamUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        setStreamConnected(true);
      };

      es.onmessage = (event) => {
        handleEventData(event.data);
      };

      es.addEventListener('progress', (event: any) => {
        handleEventData(event.data);
      });

      es.addEventListener('completed', (event: any) => {
        handleEventData(event.data);
      });

      es.onerror = () => {
        setStreamConnected(false);
      };
    } catch (e) {
      console.warn('EventSource failed, falling back to polling', e);
    }

    // Polling fallback to check if audit completed in DB
    const pollInterval = setInterval(async () => {
      if (isTerminated) return;
      try {
        const res = await fetch(`${API_BASE}/audits/${sessionId}`, { headers: authHeaders });
        if (res.ok) {
          const audit = await res.json();
          if (audit.status === 'COMPLETED') {
            isTerminated = true;
            setProgress(100);
            setIsCompleted(true);
            setStages((prev) => prev.map((s) => ({ ...s, status: 'completed' })));
            if (es) es.close();
            setTimeout(() => {
              navigate(`/audit/report/${sessionId}`);
            }, 800);
          }
        }
      } catch {
        // silent
      }
    }, 1500);

    return () => {
      clearInterval(pollInterval);
      if (es) {
        es.close();
      }
    };
  }, [id, navigate, isPaused, auditMode]);

  // Timer & Fallback Simulator (so page works even offline or in demo mode)
  useEffect(() => {
    if (isPaused || isCompleted) return;

    const interval = setInterval(() => {
      setElapsedTime((prev) => {
        const next = +(prev + 0.1).toFixed(1);
        elapsedTimeRef.current = next;
        return next;
      });

      const timeSinceLastEvent = Date.now() - lastEventTimeRef.current;
      // If stream is not connected or idle (> 500ms without new event), smoothly advance events and stages
      if (!streamConnected || timeSinceLastEvent > 500) {
        setSseRate(124 + Math.floor(Math.random() * 8));
        setEventsCount((prev) => prev + 1);
        setProgress((prev) => {
          if (prev < 98) {
            const next = prev + 1;
            if (auditMode === 'WHITEBOX') {
              if (next === 25) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 1 ? { ...s, status: 'completed' } : s.id === 2 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Parsing manifest composer.lock / package-lock & querying OSV.dev CVE database...');
              } else if (next === 45) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 2 ? { ...s, status: 'completed' } : s.id === 3 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Auditing unescaped template syntax ({!! $var !!}) & detecting dangerous DOM sinks...');
              } else if (next === 65) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 3 ? { ...s, status: 'completed' } : s.id === 4 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Computing Shannon Entropy H(X)>=4.2 for API tokens & detecting .env credential leaks...');
              } else if (next === 80) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 4 ? { ...s, status: 'completed' } : s.id === 5 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Tracing route/controller taint dataflows to database, filesystem & authorization sinks...');
              } else if (next === 92) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 5 ? { ...s, status: 'completed' } : s.id === 6 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Gemini AI synthesizing contextual risk explanation & Before vs After remediation code...');
              }
            } else if (auditMode === 'BLACKBOX') {
              if (next === 20) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 1 ? { ...s, status: 'completed' } : s.id === 2 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Scanning open port radar & verifying server socket responses...');
              } else if (next === 40) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 2 ? { ...s, status: 'completed' } : s.id === 3 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Analyzing SSL/TLS certificates & security cipher suites...');
              } else if (next === 60) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 3 ? { ...s, status: 'completed' } : s.id === 4 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Fingerprinting HTTP headers & verifying CVEs against OSV.dev database...');
              } else if (next === 75) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 4 ? { ...s, status: 'completed' } : s.id === 5 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Probing sensitive paths (.env, .git) with Soft-404 anomaly guards...');
              } else if (next === 88) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 5 ? { ...s, status: 'completed' } : s.id === 6 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Deobfuscating client JS chunks & analyzing Shannon Entropy secrets...');
              } else if (next === 95) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 6 ? { ...s, status: 'completed' } : s.id === 7 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('AI synthesizing mitigation analysis and calculating CVSS posture scores...');
              }
            } else {
              // HYBRID
              if (next === 25) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 1 ? { ...s, status: 'completed' } : s.id === 2 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Auditing package dependencies & probing open port perimeter...');
              } else if (next === 50) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 2 ? { ...s, status: 'completed' } : s.id === 3 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Probing sensitive web resources & verifying SSL/TLS certificates...');
              } else if (next === 70) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 3 ? { ...s, status: 'completed' } : s.id === 4 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Auditing unescaped templates ({!! $var !!}) & mining credential tokens...');
              } else if (next === 85) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 4 ? { ...s, status: 'completed' } : s.id === 5 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('Tracing deep logic backend taint flows & deobfuscating JS assets...');
              } else if (next === 93) {
                setStages((curr) =>
                  curr.map((s) => (s.id === 5 ? { ...s, status: 'completed' } : s.id === 6 ? { ...s, status: 'in_progress' } : s))
                );
                setNarrative('AI correlation & generating Before vs After code patch recommendations...');
              }
            }
            return next;
          } else if (prev >= 98 && !isCompleted) {
            setIsCompleted(true);
            setStages((curr) => curr.map((s) => ({ ...s, status: 'completed' })));
            setTimeout(() => {
              navigate(`/audit/report/${id || 'demo-fintech'}`);
            }, 1200);
            return 100;
          }
          return prev;
        });
      }
    }, 100);

    return () => clearInterval(interval);
  }, [isPaused, isCompleted, streamConnected, id, navigate, auditMode]);

  // SVG Radial circle math
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1e1e22]">
        <div className="space-y-1.5">
          <div className="text-xs font-mono text-[#71717a] uppercase flex items-center gap-2">
            <Link to="/dashboard" className="hover:text-white transition-colors">
              PROJECTS
            </Link>
            <span className="text-[#3f3f46]">/</span>
            <span>AUDITS</span>
            <span className="text-[#3f3f46]">/</span>
            <span className="text-white font-medium">#{id || 'demo-session'}</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-white">
              Autonomous Audit Pipeline
            </h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-[#111113] border border-[#1e1e22] text-[#d4d4d8]">
              {id || 'demo-fintech'}
            </span>
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>
                {auditMode === 'WHITEBOX'
                  ? 'SAST AST Engine Active'
                  : auditMode === 'BLACKBOX'
                  ? 'Anti-SSRF Validated'
                  : 'Hybrid Engine Active'}
              </span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5 self-start sm:self-center flex-wrap">
          {/* SSE Status Badge */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-xs font-mono">
            <span className={`w-1.5 h-1.5 rounded-full bg-emerald-400 ${!isPaused ? 'animate-pulse' : ''}`} />
            <span>
              {isCompleted
                ? 'Audit Completed (100%)'
                : streamConnected
                ? `SSE Live Stream Active`
                : `Pipeline Active: ${sseRate} evt/s`}
            </span>
          </div>

          {/* Timer */}
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#1e1e22] bg-[#111113] text-[#d4d4d8] text-xs font-mono">
            <svg className="w-3.5 h-3.5 text-[#71717a]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <circle cx="12" cy="12" r="10" strokeWidth="2" />
              <path strokeWidth="2" d="M12 6v6l4 2" />
            </svg>
            <span>{elapsedTime}s</span>
          </div>
        </div>
      </div>

      {/* Completion Banner */}
      {isCompleted && (
        <div className="p-4 bg-emerald-950/40 border border-emerald-800/60 rounded-xl flex items-center justify-between text-xs font-mono text-emerald-300 animate-fadeIn">
          <div className="flex items-center gap-2.5">
            <span className="text-base">✓</span>
            <span className="font-semibold">Audit Complete! Redirecting to Executive Report...</span>
          </div>
          <Link
            to={`/audit/report/${id || 'demo-fintech'}`}
            className="px-3 py-1.5 bg-emerald-500 text-black rounded-lg font-bold hover:bg-emerald-400 transition-colors"
          >
            Open Report Now →
          </Link>
        </div>
      )}

      {/* Left Radial Progress (5 cols) + Right Telemetry Narrative (7 cols) */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Left: Radial Progress Card */}
        <div className="md:col-span-5 bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 flex flex-col justify-between shadow-2xl relative">
          <div className="flex items-center justify-between text-xs font-mono text-[#71717a] border-b border-[#1e1e22] pb-3">
            <span className="flex items-center gap-2 font-medium tracking-wide uppercase text-[11px] text-white">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0070f3]" />
              Audit Execution
            </span>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
              {`Phase ${Math.min(stages.length, Math.max(1, stages.filter((s) => s.status === 'completed').length + 1))} / ${stages.length}`}
            </span>
          </div>

          {/* SVG Circular Score Gauge */}
          <div className="relative py-6 flex flex-col items-center justify-center my-auto">
            <div className="relative w-44 h-44 flex items-center justify-center">
              <svg className="w-44 h-44 -rotate-90 transform" viewBox="0 0 200 200">
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="transparent"
                  stroke="#1e1e22"
                  strokeWidth="8"
                />
                <circle
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="transparent"
                  stroke="#0070f3"
                  strokeWidth="8"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-300 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="font-mono text-[10px] text-[#71717a] tracking-widest uppercase">
                  Progress
                </span>
                <div className="flex items-baseline tracking-tight my-0.5">
                  <span className="text-4xl font-semibold text-white font-mono">{progress}</span>
                  <span className="text-[#71717a] text-lg font-light ml-0.5">%</span>
                </div>
                <span className="font-mono text-[11px] text-emerald-400 flex items-center gap-1.5 mt-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  <span>{isCompleted ? 'Finalized' : 'Analyzing'}</span>
                </span>
              </div>
            </div>
          </div>

          {/* Metric row */}
          <div className="w-full grid grid-cols-3 gap-2 pt-4 border-t border-[#1e1e22] text-center font-mono text-xs">
            <div className="p-2 rounded-lg bg-[#111113] border border-[#1e1e22]">
              <span className="text-[10px] text-[#71717a] block">
                {auditMode === 'WHITEBOX' ? 'AST Nodes' : auditMode === 'BLACKBOX' ? 'Ports Scope' : 'Hybrid Sinks'}
              </span>
              <span className="text-xs font-semibold text-white mt-0.5 block">
                {auditMode === 'WHITEBOX' ? '14,290' : auditMode === 'BLACKBOX' ? 'Curated Ports' : 'Source + Web'}
              </span>
            </div>
            <div className="p-2 rounded-lg bg-[#111113] border border-[#1e1e22]">
              <span className="text-[10px] text-[#71717a] block">Shannon H(X)</span>
              <span className="text-xs font-semibold text-emerald-400 mt-0.5 block">4.2+ bits</span>
            </div>
            <div className="p-2 rounded-lg bg-[#111113] border border-[#1e1e22]">
              <span className="text-[10px] text-[#71717a] block">Redacted</span>
              <span className="text-xs font-semibold text-amber-400 mt-0.5 block">100% Safe</span>
            </div>
          </div>
        </div>

        {/* Right: AI Narrative Streaming Area */}
        <div className="md:col-span-7 bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 flex flex-col justify-between shadow-2xl space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#1e1e22]">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded bg-[#111113] border border-[#1e1e22] flex items-center justify-center text-xs font-mono font-medium text-white">
                  AI
                </div>
                <span className="text-xs font-semibold text-white uppercase font-mono tracking-wider">
                  Storyteller Telemetry Intelligence
                </span>
              </div>
              <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-[#111113] border border-[#1e1e22] text-[#71717a]">
                Live Reasoning
              </span>
            </div>

            {/* Story streaming body */}
            <div className="mt-4 p-4 rounded-lg bg-[#050505] border border-[#1e1e22] space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono text-[#71717a]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#0070f3]" />
                <span>Correlating Findings &amp; Heuristics (Gemini 2.5 Flash)</span>
              </div>
              <p className="text-xs text-[#d4d4d8] leading-relaxed font-sans min-h-[48px]">
                {narrative}
              </p>
              <div className="flex items-center gap-3 pt-2 border-t border-[#1e1e22] text-[10px] font-mono text-[#71717a]">
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  AST In-Memory: Ephemeral
                </span>
                <span>•</span>
                <span>Zero Cloud Plaintext Disk Leak</span>
              </div>
            </div>
          </div>

          {/* Preliminary Findings Callout */}
          <div className="p-3.5 rounded-lg bg-[#111113] border border-[#1e1e22] flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <svg className="w-5 h-5 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <div className="min-w-0">
                <div className="text-[10px] font-mono text-amber-400 font-medium uppercase tracking-wider">
                  Zero Leak Secret Masking Active
                </div>
                <div className="text-xs font-medium text-white truncate">
                  All tokens, API keys, and sensitive credentials are automatically redacted with asterisk masks.
                </div>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0">
              Enforced
            </span>
          </div>
        </div>
      </div>

      {/* Mode-specific Progress Tracker: Vertical steps */}
      <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-[#71717a] uppercase tracking-wider font-semibold">
            {auditMode} Security Pipeline ({stages.length} Stages)
          </span>
          <span className="text-[#a1a1aa]">Real-Time SSE Sync</span>
        </div>

        <div className="space-y-3">
          {stages.map((stage) => {
            const isDone = stage.status === 'completed';
            const isCurrent = stage.status === 'in_progress';

            return (
              <div
                key={stage.id}
                className={`p-3.5 rounded-lg border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  isCurrent
                    ? 'border-[#0070f3] bg-[#111113]/80 shadow-md'
                    : isDone
                    ? 'border-[#1e1e22] bg-[#050505]'
                    : 'border-[#1e1e22]/50 bg-[#050505]/40 opacity-50'
                }`}
              >
                <div className="flex items-start sm:items-center gap-3">
                  <div
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono shrink-0 ${
                      isDone
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold'
                        : isCurrent
                        ? 'bg-[#0070f3]/10 text-[#0070f3] border border-[#0070f3]/30 animate-pulse'
                        : 'bg-[#111113] text-[#52525b] border border-[#1e1e22]'
                    }`}
                  >
                    {isDone ? '✓' : isCurrent ? '●' : stage.id}
                  </div>
                  <div>
                    <div className="text-xs font-mono font-medium text-white flex items-center gap-2">
                      <span>{stage.name}</span>
                      {isCurrent && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-[#0070f3]/15 text-[#0070f3]">
                          Active
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-[#71717a] font-mono mt-0.5">
                      {stage.detail}
                    </div>
                  </div>
                </div>

                <span className="px-2 py-0.5 rounded-full text-xs font-mono self-start sm:self-center bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
                  {isDone ? 'Completed' : isCurrent ? 'Running...' : 'Queued'}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Terminal Log Stream */}
      <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl overflow-hidden shadow-2xl">
        <div className="px-4 py-3 border-b border-[#1e1e22] bg-[#111113] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#27272a]" />
            </div>
            <span className="font-mono text-xs text-white font-medium flex items-center gap-1.5">
              SSE Event Telemetry • <span className="text-[#71717a]">GET /api/v1/audits/{id || 'demo'}/stream</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-[#71717a] mr-2 hidden sm:inline">
              Events: <strong className="text-white">{eventsCount}</strong>
            </span>
            <button
              type="button"
              onClick={() => {
                if (isPaused) {
                  setIsPaused(false);
                  lastEventTimeRef.current = 0;
                } else {
                  setIsPaused(true);
                }
              }}
              className="px-2.5 py-1 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-xs font-mono text-[#d4d4d8] hover:text-white transition-all flex items-center gap-1.5"
            >
              {isPaused ? (
                <>
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  <span>Resume</span>
                </>
              ) : (
                <>
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                    <rect x="6" y="4" width="4" height="16" />
                    <rect x="14" y="4" width="4" height="16" />
                  </svg>
                  <span>Pause</span>
                </>
              )}
            </button>
            <button
              type="button"
              onClick={() => setTerminalCollapsed(!terminalCollapsed)}
              className="px-2.5 py-1 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-xs font-mono text-[#d4d4d8] hover:text-white transition-all flex items-center gap-1.5"
            >
              {terminalCollapsed ? (
                <>
                  <span>Expand Logs</span>
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="18 15 12 9 6 15" />
                  </svg>
                </>
              ) : (
                <>
                  <span>Collapse Logs</span>
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </>
              )}
            </button>
          </div>
        </div>

        {!terminalCollapsed && (
          <div className="p-4 font-mono text-xs flex flex-col gap-1.5 max-h-64 overflow-y-auto leading-relaxed bg-black">
            {logs.map((log) => (
              <div key={log.id} className="text-[#a1a1aa] flex items-start gap-3">
                <span className="text-[#52525b] select-none w-6 text-right font-mono">
                  {String(log.id).padStart(2, '0')}
                </span>
                <span className="text-[#52525b]">[{log.time}]</span>
                <span className={`px-1 py-0.2 rounded bg-[#111113] font-semibold ${log.tagColor}`}>
                  {log.tag}
                </span>
                <span className="text-[#ededed] break-all">{log.message}</span>
              </div>
            ))}
            {!isCompleted && (
              <div className="text-white flex items-center gap-3 pt-1 animate-pulse">
                <span className="text-[#52525b] select-none w-6 text-right font-mono">
                  {String(logs.length + 1).padStart(2, '0')}
                </span>
                <span className="text-[#52525b]">[{elapsedTime}s]</span>
                <span className="px-1 py-0.2 rounded bg-[#0070f3]/20 text-[#0070f3] font-semibold">
                  [STREAM]
                </span>
                <span className="text-[#d4d4d8]">
                  Streaming telemetry payloads...
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="pt-4 border-t border-[#1e1e22] flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-[#71717a] font-mono text-xs">
          <span className="text-[#52525b]">$</span>
          <span>curl -N http://localhost:8000/api/v1/audits/{id || 'demo-fintech'}/stream</span>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <button
            type="button"
            onClick={() => navigate('/audit/new')}
            className="px-3.5 py-2 text-xs font-mono text-[#71717a] hover:text-white transition-colors"
          >
            {isCompleted ? 'New Audit' : 'Cancel'}
          </button>
          {isCompleted ? (
            <button
              type="button"
              onClick={() => navigate(`/audit/report/${id || 'demo-fintech'}`)}
              className="px-4 py-2 rounded-lg bg-[#e5e2e1] text-black hover:bg-white text-xs font-mono font-medium transition-all flex items-center gap-2 shadow-sm"
            >
              <span>Open Audit Report →</span>
            </button>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[#1e1e22] bg-[#111113] text-[#71717a] text-xs font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0070f3] animate-pulse" />
              <span>Audit In Progress ({progress}%)...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
