import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { getAuditsList, deleteAudit, batchDeleteAudits, type AuditSummaryItem } from '../lib/api';

/* ------------------------------------------------------------------ */
/*  Interfaces & Demo Data                                            */
/* ------------------------------------------------------------------ */

interface Project {
  id?: string;
  name: string;
  grade: string;
  gradeLabel: string;
  score: number;
  auditType: string;
  repo: string;
  branch: string;
  vulnSummary: string;
  vulnColor: string;
  timeAgo: string;
  scanDuration: string;
  dotColor: string;
  iconBg: string;
  iconColor: string;
  iconType: 'warning' | 'check' | 'shield' | 'zap';
  gradeBg: string;
  gradeColor: string;
  dotPing?: boolean;
  hasSimulatePatch?: boolean;
  criticalCount?: number;
  highCount?: number;
  environment: 'Prod' | 'Staging' | 'Dev';
}

interface ColumnVisibility {
  badges: boolean;
  repo: boolean;
  branch: boolean;
  vulnSummary: boolean;
  scanTime: boolean;
}

type GradeFilter = 'All' | 'Grade A' | 'Grade B' | 'Grade C/D';
type SeverityFilter = 'All' | 'Critical' | 'High' | 'Medium' | 'Low';
type EnvFilter = 'All' | 'Prod & Staging' | 'Prod' | 'Staging';
type SortOption = 'recent' | 'score_desc' | 'score_asc' | 'vulns' | 'name';

const DEFAULT_PROJECTS: Project[] = [
  {
    id: 'demo-fintech',
    name: 'Fintech Payment Core',
    grade: 'D',
    gradeLabel: 'Grade D (38/100)',
    score: 38,
    auditType: 'Hybrid Audit (DAST + SAST)',
    repo: 'https://demo-fintech.auraglass.io',
    branch: 'main',
    vulnSummary: '2 Critical, 1 High',
    vulnColor: 'text-red-400',
    timeAgo: '12m ago',
    scanDuration: '24.2s scan',
    dotColor: 'bg-red-400',
    iconBg: 'bg-red-500/10',
    iconColor: 'text-red-400',
    iconType: 'warning',
    gradeBg: 'bg-red-500/15',
    gradeColor: 'text-red-400',
    dotPing: false,
    hasSimulatePatch: true,
    criticalCount: 2,
    highCount: 1,
    environment: 'Prod',
  },
];

function formatTimeAgo(dateString?: string): string {
  if (!dateString) return 'Recently';
  try {
    const diffMs = Date.now() - new Date(dateString).getTime();
    if (diffMs < 0 || isNaN(diffMs)) return 'Just now';
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days === 1) return 'Yesterday';
    return `${days}d ago`;
  } catch {
    return 'Recently';
  }
}

function getExportDateString(): string {
  return new Date().toISOString().slice(0, 10);
}

/* ------------------------------------------------------------------ */
/*  Inline SVG Icons                                                  */
/* ------------------------------------------------------------------ */

function SearchIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

function ChevronRight() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m9 18 6-6-6-6" />
    </svg>
  );
}

function ReplayIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 1 1 3-6.36" />
      <path d="M3 3v6h6" />
    </svg>
  );
}

function ColumnsIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="18" height="18" x="3" y="3" rx="2" />
      <path d="M9 3v18" />
      <path d="M15 3v18" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" x2="12" y1="15" y2="3" />
    </svg>
  );
}

function PlusIcon({ className }: { className?: string }) {
  return (
    <svg className={className} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12h14" />
      <path d="M12 5v14" />
    </svg>
  );
}

function ChevronDown() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

function SortIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m3 16 4 4 4-4" />
      <path d="M7 20V4" />
      <path d="m21 8-4-4-4 4" />
      <path d="M17 4v16" />
    </svg>
  );
}

function CodeIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  );
}

function BranchIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="6" x2="6" y1="3" y2="15" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </svg>
  );
}

function TrashIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6h18" />
      <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
      <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
      <line x1="10" x2="11" y1="11" y2="17" />
      <line x1="14" x2="13" y1="11" y2="17" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function FolderIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" />
    </svg>
  );
}

function ShieldIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function AlertTriangleIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

function WrenchIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  );
}

function CheckCircleIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}

function ZapIcon({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

function SearchEmptyIcon({ className = 'w-6 h-6' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function XIcon({ className = 'w-3 h-3' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function renderProjectIcon(type: string, className = 'w-4 h-4') {
  switch (type) {
    case 'warning':
      return <AlertTriangleIcon className={className} />;
    case 'check':
      return <CheckCircleIcon className={className} />;
    case 'shield':
      return <ShieldIcon className={className} />;
    case 'zap':
      return <ZapIcon className={className} />;
    default:
      return <ShieldIcon className={className} />;
  }
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function DashboardPage() {
  const [activeFilter, setActiveFilter] = useState<GradeFilter>('All');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('All');
  const [envFilter, setEnvFilter] = useState<EnvFilter>('Prod & Staging');
  const [sortOption, setSortOption] = useState<SortOption>('recent');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [projectList, setProjectList] = useState<Project[]>(DEFAULT_PROJECTS);

  // Modals & Popovers
  const [showColumnsMenu, setShowColumnsMenu] = useState(false);
  const [showEnvMenu, setShowEnvMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [projectToDelete, setProjectToDelete] = useState<Project | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Column Customization
  const [visibleColumns, setVisibleColumns] = useState<ColumnVisibility>({
    badges: true,
    repo: true,
    branch: true,
    vulnSummary: true,
    scanTime: true,
  });

  // Pagination & Custom Rows
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState<number>(10);
  const [customRowsInput, setCustomRowsInput] = useState<string>('10');
  const [showRowsDropdown, setShowRowsDropdown] = useState<boolean>(false);

  // Multi-selection & Batch Delete
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showBatchDeleteModal, setShowBatchDeleteModal] = useState<boolean>(false);
  const [isDeletingBatch, setIsDeletingBatch] = useState<boolean>(false);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const columnsRef = useRef<HTMLDivElement>(null);
  const envRef = useRef<HTMLDivElement>(null);
  const sortRef = useRef<HTMLDivElement>(null);
  const rowsRef = useRef<HTMLDivElement>(null);

  // Fetch audits from backend
  useEffect(() => {
    let isMounted = true;
    const loadAudits = async () => {
      setLoading(true);
      try {
        const audits = await getAuditsList();
        if (!isMounted) return;
        const apiProjects: Project[] = (audits || []).map((a: AuditSummaryItem) => {
          const isCrit = (a.critical_count || 0) > 0;
          const isHigh = (a.high_count || 0) > 0;
          const score = typeof a.score === 'number' ? a.score : 0;
          const grade = a.grade || (score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F');
          const isA = grade === 'A';
          const isB = grade === 'B';
          const isC = grade === 'C';

          let vulnSummary = 'Clean & Hardened (0 Findings)';
          if (isCrit && isHigh) {
            vulnSummary = `${a.critical_count} Critical, ${a.high_count} High`;
          } else if (isCrit) {
            vulnSummary = `${a.critical_count} Critical Vulnerabilities`;
          } else if (isHigh) {
            vulnSummary = `${a.high_count} High Vulnerabilities`;
          }

          const repoStr = a.github_repo_url || a.target_url || a.session_id;
          const isStaging =
            (repoStr || '').toLowerCase().includes('staging') ||
            (a.project_name || '').toLowerCase().includes('staging') ||
            (a.branch || '').toLowerCase().includes('staging');

          return {
            id: a.session_id,
            name: a.project_name || a.session_id,
            grade,
            gradeLabel: `Grade ${grade} (${score}/100)`,
            score,
            auditType: a.mode === 'HYBRID' ? 'Hybrid Audit' : a.mode === 'WHITEBOX' ? 'Whitebox SAST' : 'Blackbox DAST',
            repo: repoStr,
            branch: a.branch || 'main',
            vulnSummary,
            vulnColor: isCrit ? 'text-red-400' : isHigh ? 'text-amber-400' : 'text-emerald-400',
            timeAgo: formatTimeAgo(a.created_at),
            scanDuration: `${((a.duration_ms || 21000) / 1000).toFixed(1)}s scan`,
            dotColor: isA ? 'bg-emerald-400' : isB ? 'bg-blue-400' : isC ? 'bg-amber-400' : 'bg-red-400',
            iconBg: isA ? 'bg-emerald-500/10' : isB ? 'bg-blue-500/10' : isC ? 'bg-amber-500/10' : 'bg-red-500/10',
            iconColor: isA ? 'text-emerald-400' : isB ? 'text-blue-400' : isC ? 'text-amber-400' : 'text-red-400',
            iconType: isA ? 'check' : isB ? 'shield' : isC ? 'zap' : 'warning',
            gradeBg: isA ? 'bg-emerald-500/15' : isB ? 'bg-blue-500/15' : isC ? 'bg-amber-500/15' : 'bg-red-500/15',
            gradeColor: isA ? 'text-emerald-400' : isB ? 'text-blue-400' : isC ? 'text-amber-400' : 'text-red-400',
            dotPing: a.status === 'RUNNING' || a.status === 'IN_PROGRESS',
            hasSimulatePatch: isCrit || isHigh,
            criticalCount: a.critical_count || 0,
            highCount: a.high_count || 0,
            environment: isStaging ? 'Staging' : 'Prod',
          };
        });

        if (apiProjects.length > 0) {
          setProjectList(apiProjects);
        } else {
          setProjectList(DEFAULT_PROJECTS);
        }
      } catch (err) {
        console.warn('Could not fetch audits from API:', err);
        setProjectList(DEFAULT_PROJECTS);
      } finally {
        if (isMounted) setLoading(false);
      }
    };
    loadAudits();
    return () => {
      isMounted = false;
    };
  }, []);

  // Keyboard shortcut: Cmd+K / Ctrl+K
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Click outside to close menus
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (columnsRef.current && !columnsRef.current.contains(event.target as Node)) {
        setShowColumnsMenu(false);
      }
      if (envRef.current && !envRef.current.contains(event.target as Node)) {
        setShowEnvMenu(false);
      }
      if (sortRef.current && !sortRef.current.contains(event.target as Node)) {
        setShowSortMenu(false);
      }
      if (rowsRef.current && !rowsRef.current.contains(event.target as Node)) {
        setShowRowsDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Dynamic Metrics Calculation
  const totalAudited = projectList.length;
  const avgHealthScore =
    totalAudited > 0 ? Math.round(projectList.reduce((acc, p) => acc + (p.score || 0), 0) / totalAudited) : 0;
  const avgHealthGrade =
    totalAudited === 0
      ? 'No Audits'
      : avgHealthScore >= 90
        ? 'Grade A'
        : avgHealthScore >= 80
          ? 'Grade B+'
          : avgHealthScore >= 70
            ? 'Grade B'
            : avgHealthScore >= 55
              ? 'Grade C'
              : avgHealthScore >= 40
                ? 'Grade D'
                : 'Grade F';

  const totalOpenCriticals = projectList.reduce((acc, p) => acc + (p.criticalCount || 0), 0);
  const totalPatches = projectList.reduce(
    (acc, p) => acc + ((p.criticalCount || 0) > 0 ? p.criticalCount! : 0) + ((p.highCount || 0) > 0 ? p.highCount! : 0),
    0
  );

  const dynamicMetrics: {
    label: string;
    value: string;
    valueSuffix?: string;
    badge?: string;
    badgeBg?: string;
    badgeColor?: string;
    sub?: string;
    subColor?: string;
    valueColor?: string;
    barWidth: string;
    barColor: string;
    icon: React.ReactNode;
  }[] = [
    {
      label: 'Audited Projects',
      value: String(totalAudited),
      sub: totalAudited > 0 ? `${totalAudited} active session${totalAudited > 1 ? 's' : ''}` : 'No active sessions',
      subColor: 'text-[#a1a1aa]',
      barWidth: `${Math.min(100, Math.round((totalAudited / 10) * 100))}%`,
      barColor: 'bg-blue-500',
      icon: <FolderIcon className="w-4 h-4 text-[#a1a1aa]" />,
    },
    {
      label: 'Average Health',
      value: totalAudited > 0 ? String(avgHealthScore) : '—',
      valueSuffix: totalAudited > 0 ? '/100' : '',
      badge: avgHealthGrade,
      badgeBg:
        totalAudited === 0
          ? 'bg-[#1e1e22]'
          : avgHealthScore >= 80
            ? 'bg-emerald-500/15'
            : avgHealthScore >= 60
              ? 'bg-blue-500/15'
              : 'bg-amber-500/15',
      badgeColor:
        totalAudited === 0
          ? 'text-[#71717a]'
          : avgHealthScore >= 80
            ? 'text-emerald-400'
            : avgHealthScore >= 60
              ? 'text-blue-400'
              : 'text-amber-400',
      barWidth: totalAudited > 0 ? `${avgHealthScore}%` : '0%',
      barColor:
        avgHealthScore >= 80 ? 'bg-emerald-500' : avgHealthScore >= 60 ? 'bg-blue-500' : 'bg-amber-500',
      icon: <ShieldIcon className="w-4 h-4 text-[#a1a1aa]" />,
    },
    {
      label: 'Open Criticals',
      value: String(totalOpenCriticals),
      sub: totalOpenCriticals > 0 ? 'Pending Remediation' : 'Clean & Hardened',
      subColor: totalOpenCriticals > 0 ? 'text-red-400' : 'text-emerald-400',
      valueColor: totalOpenCriticals > 0 ? 'text-red-400' : 'text-white',
      barWidth: totalOpenCriticals > 0 ? `${Math.min(100, Math.max(15, totalOpenCriticals * 20))}%` : '0%',
      barColor: totalOpenCriticals > 0 ? 'bg-red-500' : 'bg-emerald-500',
      icon: <AlertTriangleIcon className={`w-4 h-4 ${totalOpenCriticals > 0 ? 'text-red-400' : 'text-[#a1a1aa]'}`} />,
    },
    {
      label: 'Automated Patches',
      value: String(totalPatches),
      sub: totalPatches > 0 ? `${totalPatches} remediations ready` : 'No patches required',
      subColor: 'text-[#71717a]',
      barWidth: totalPatches > 0 ? `${Math.min(100, totalPatches * 25)}%` : '0%',
      barColor: 'bg-violet-500',
      icon: <WrenchIcon className="w-4 h-4 text-[#a1a1aa]" />,
    },
  ];

  // Filter & Sort Logic
  const filteredProjects = projectList
    .filter((p) => {
      // Grade filter
      const matchesGrade =
        activeFilter === 'All' ||
        (activeFilter === 'Grade A' && p.grade === 'A') ||
        (activeFilter === 'Grade B' && p.grade === 'B') ||
        (activeFilter === 'Grade C/D' && (p.grade === 'C' || p.grade === 'D' || p.grade === 'F'));

      // Environment filter
      const matchesEnv =
        envFilter === 'All' ||
        (envFilter === 'Prod & Staging' && (p.environment === 'Prod' || p.environment === 'Staging')) ||
        (envFilter === 'Prod' && p.environment === 'Prod') ||
        (envFilter === 'Staging' && (p.environment === 'Staging' || p.environment === 'Dev'));

      // Severity filter
      const matchesSeverity =
        severityFilter === 'All' ||
        (severityFilter === 'Critical' && (p.criticalCount || 0) > 0) ||
        (severityFilter === 'High' && (p.highCount || 0) > 0) ||
        (severityFilter === 'Medium' && (p.vulnSummary?.toLowerCase().includes('medium') || p.grade === 'B' || p.grade === 'C')) ||
        (severityFilter === 'Low' && (p.vulnSummary?.toLowerCase().includes('low') || p.grade === 'A'));

      // Search query
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        p.name.toLowerCase().includes(q) ||
        p.repo.toLowerCase().includes(q) ||
        p.branch.toLowerCase().includes(q) ||
        p.vulnSummary.toLowerCase().includes(q) ||
        p.auditType.toLowerCase().includes(q) ||
        (p.id && p.id.toLowerCase().includes(q));

      return matchesGrade && matchesEnv && matchesSeverity && matchesSearch;
    })
    .sort((a, b) => {
      if (sortOption === 'score_desc') return b.score - a.score;
      if (sortOption === 'score_asc') return a.score - b.score;
      if (sortOption === 'vulns') {
        const critB = b.criticalCount || 0;
        const critA = a.criticalCount || 0;
        const highB = b.highCount || 0;
        const highA = a.highCount || 0;
        return critB * 10 + highB - (critA * 10 + highA);
      }
      if (sortOption === 'name') return a.name.localeCompare(b.name);
      return 0; // recent order default
    });

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredProjects.length / itemsPerPage));
  const currentSafePage = Math.min(currentPage, totalPages);
  const startIndex = (currentSafePage - 1) * itemsPerPage;
  const paginatedProjects = filteredProjects.slice(startIndex, startIndex + itemsPerPage);

  // Export CSV functionality
  const handleExportCSV = () => {
    try {
      const headers = [
        'Project Name',
        'Session ID',
        'Audit Mode',
        'Grade',
        'Score',
        'Environment',
        'Target / Repository',
        'Branch',
        'Vulnerabilities',
        'Scan Duration',
        'Timestamp',
      ];

      const rows = filteredProjects.map((p) => [
        `"${(p.name || '').replace(/"/g, '""')}"`,
        `"${(p.id || '').replace(/"/g, '""')}"`,
        `"${p.auditType}"`,
        `"${p.grade}"`,
        p.score,
        `"${p.environment}"`,
        `"${(p.repo || '').replace(/"/g, '""')}"`,
        `"${p.branch}"`,
        `"${(p.vulnSummary || '').replace(/"/g, '""')}"`,
        `"${p.scanDuration}"`,
        `"${p.timeAgo}"`,
      ]);

      const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const nowStr = getExportDateString();
      link.setAttribute('href', url);
      link.setAttribute('download', `secaudit-directory-export-${nowStr}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setToastMessage(`CSV successfully exported (${filteredProjects.length} projects)`);
      setTimeout(() => setToastMessage(null), 3000);
    } catch (err) {
      console.error('Export CSV failed:', err);
    }
  };

  // Delete single project confirmation
  const handleConfirmDelete = async () => {
    if (!projectToDelete) return;
    setIsDeleting(true);

    try {
      if (projectToDelete.id) {
        await deleteAudit(projectToDelete.id);
      }
      // Remove from local list & selection
      setProjectList((prev) => prev.filter((p) => (p.id ? p.id !== projectToDelete.id : p.name !== projectToDelete.name)));
      setSelectedIds((prev) => prev.filter((id) => id !== projectToDelete.id && id !== projectToDelete.name));
      setToastMessage(`Audit session "${projectToDelete.name}" successfully deleted.`);
      setTimeout(() => setToastMessage(null), 3500);
    } catch (err) {
      console.error('Failed to delete audit:', err);
      // Fallback local remove
      setProjectList((prev) => prev.filter((p) => (p.id ? p.id !== projectToDelete.id : p.name !== projectToDelete.name)));
      setSelectedIds((prev) => prev.filter((id) => id !== projectToDelete.id && id !== projectToDelete.name));
      setToastMessage(`Audit project "${projectToDelete.name}" removed from dashboard.`);
      setTimeout(() => setToastMessage(null), 3500);
    } finally {
      setIsDeleting(false);
      setProjectToDelete(null);
    }
  };

  // Batch delete projects confirmation
  const handleConfirmBatchDelete = async () => {
    if (selectedIds.length === 0) return;
    setIsDeletingBatch(true);

    try {
      const validDbIds = selectedIds.filter((id) =>
        projectList.some((p) => p.id === id)
      );

      if (validDbIds.length > 0) {
        await batchDeleteAudits(validDbIds);
      }

      // Remove from local list
      setProjectList((prev) =>
        prev.filter((p) => !selectedIds.includes(p.id || p.name))
      );
      setToastMessage(`${selectedIds.length} audit sessions successfully deleted.`);
      setTimeout(() => setToastMessage(null), 3500);
      setSelectedIds([]);
    } catch (err) {
      console.error('Failed to batch delete audits:', err);
      // Fallback local remove
      setProjectList((prev) =>
        prev.filter((p) => !selectedIds.includes(p.id || p.name))
      );
      setToastMessage(`${selectedIds.length} audit projects removed from dashboard.`);
      setTimeout(() => setToastMessage(null), 3500);
      setSelectedIds([]);
    } finally {
      setIsDeletingBatch(false);
      setShowBatchDeleteModal(false);
    }
  };

  // Selection handlers
  const paginatedProjectIds = paginatedProjects.map((p) => p.id || p.name);
  const isAllCurrentPageSelected =
    paginatedProjects.length > 0 &&
    paginatedProjectIds.every((id) => selectedIds.includes(id));
  const isSomeCurrentPageSelected =
    paginatedProjects.some((p) => selectedIds.includes(p.id || p.name)) &&
    !isAllCurrentPageSelected;

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const toggleSelectAllCurrentPage = () => {
    if (isAllCurrentPageSelected) {
      setSelectedIds((prev) =>
        prev.filter((id) => !paginatedProjectIds.includes(id))
      );
    } else {
      setSelectedIds((prev) =>
        Array.from(new Set([...prev, ...paginatedProjectIds]))
      );
    }
  };

  const selectAllFiltered = () => {
    const allFilteredIds = filteredProjects.map((p) => p.id || p.name);
    setSelectedIds(allFilteredIds);
  };

  const clearSelection = () => {
    setSelectedIds([]);
  };

  // Smart pagination windowing
  const getPaginationNumbers = () => {
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, i) => i + 1);
    }
    if (currentSafePage <= 4) {
      return [1, 2, 3, 4, 5, '...', totalPages];
    }
    if (currentSafePage >= totalPages - 3) {
      return [1, '...', totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
    }
    return [1, '...', currentSafePage - 1, currentSafePage, currentSafePage + 1, '...', totalPages];
  };

  return (
    <div className="pt-8 pb-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full min-w-0 overflow-x-clip">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl bg-[#111113] border border-[#27272a] text-[#ededed] text-xs font-mono shadow-2xl animate-in fade-in slide-in-from-bottom duration-200">
          <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {projectToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#0a0a0a] border border-[#27272a] rounded-xl p-6 max-w-md w-full shadow-2xl flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
                <TrashIcon />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">Delete Audit Session?</h3>
                <p className="text-xs text-[#71717a] font-mono mt-0.5">This action is permanent and cannot be undone</p>
              </div>
            </div>

            <p className="text-xs text-[#a1a1aa] leading-relaxed">
              Are you sure you want to permanently delete the audit project for{' '}
              <strong className="text-white">{projectToDelete.name}</strong>? All associated vulnerability findings, raw telemetry, and AI remediation patches will be eradicated.
            </p>

            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setProjectToDelete(null)}
                disabled={isDeleting}
                className="px-3.5 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed] text-xs font-mono transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-medium transition-colors flex items-center gap-2"
              >
                {isDeleting ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Deleting...</span>
                  </>
                ) : (
                  <>
                    <TrashIcon />
                    <span>Delete Project</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Batch Delete Confirmation Modal */}
      {showBatchDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#0a0a0a] border border-[#27272a] rounded-xl p-6 max-w-md w-full shadow-2xl flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
                <TrashIcon />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">Delete {selectedIds.length} Audit Sessions?</h3>
                <p className="text-xs text-[#71717a] font-mono mt-0.5">This action is permanent and cannot be undone</p>
              </div>
            </div>

            <p className="text-xs text-[#a1a1aa] leading-relaxed">
              Are you sure you want to permanently purge <strong className="text-white">{selectedIds.length} selected audit projects</strong> in bulk? All associated vulnerability records, network logs, and AI remediation history will be permanently deleted from the database.
            </p>

            <div className="p-2.5 rounded-lg bg-[#111113] border border-[#1e1e22] max-h-36 overflow-y-auto space-y-1.5">
              {projectList
                .filter((p) => selectedIds.includes(p.id || p.name))
                .slice(0, 5)
                .map((p) => (
                  <div key={p.id || p.name} className="text-[11px] font-mono text-[#d4d4d8] truncate flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                    <span className="truncate">{p.name}</span>
                  </div>
                ))}
              {selectedIds.length > 5 && (
                <div className="text-[10px] font-mono text-[#71717a] italic pt-1 pl-3.5">
                  + {selectedIds.length - 5} additional audit projects
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setShowBatchDeleteModal(false)}
                disabled={isDeletingBatch}
                className="px-3.5 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed] text-xs font-mono transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmBatchDelete}
                disabled={isDeletingBatch}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-medium transition-colors flex items-center gap-2 shadow-sm"
              >
                {isDeletingBatch ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Deleting {selectedIds.length} Audits...</span>
                  </>
                ) : (
                  <>
                    <TrashIcon />
                    <span>Purge Selected Audits</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================ */}
      {/*  1. Header Row                                                */}
      {/* ============================================================ */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-8">
        <div className="flex flex-col gap-1.5">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider">
            <span className="text-[#71717a]">Directory</span>
            <span className="text-[#3f3f46]">/</span>
            <span className="text-[#a1a1aa]">Active Security Telemetry</span>
          </div>

          <h1 className="text-2xl font-semibold tracking-tight text-white">
            Audit Directory
          </h1>

          <p className="text-sm text-[#71717a] max-w-xl leading-relaxed">
            Automated vulnerability scans, runtime behavioral maps, and continuous
            mitigation audits across your perimeter endpoints.
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-2.5 shrink-0">
          {/* Columns Toggle Dropdown */}
          <div className="relative" ref={columnsRef}>
            <button
              type="button"
              onClick={() => {
                setShowColumnsMenu((prev) => !prev);
                setShowEnvMenu(false);
                setShowSortMenu(false);
              }}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed] text-xs font-mono transition-colors"
            >
              <ColumnsIcon />
              <span>Columns</span>
            </button>

            {showColumnsMenu && (
              <div className="absolute left-0 sm:left-auto sm:right-0 mt-2 w-56 max-w-[calc(100vw-2rem)] rounded-xl bg-[#0a0a0a] border border-[#27272a] shadow-2xl p-2 z-40 flex flex-col gap-1">
                <span className="text-[10px] font-mono text-[#71717a] uppercase px-2 py-1 tracking-wider">
                  Toggle Columns
                </span>

                <button
                  type="button"
                  onClick={() => setVisibleColumns((c) => ({ ...c, badges: !c.badges }))}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono hover:bg-[#161618] text-[#ededed] transition-colors"
                >
                  <span>Audit Mode Badges</span>
                  <span className={visibleColumns.badges ? 'text-emerald-400' : 'text-[#3f3f46]'}>
                    {visibleColumns.badges ? <CheckIcon /> : '—'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setVisibleColumns((c) => ({ ...c, repo: !c.repo }))}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono hover:bg-[#161618] text-[#ededed] transition-colors"
                >
                  <span>Repository URL</span>
                  <span className={visibleColumns.repo ? 'text-emerald-400' : 'text-[#3f3f46]'}>
                    {visibleColumns.repo ? <CheckIcon /> : '—'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setVisibleColumns((c) => ({ ...c, branch: !c.branch }))}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono hover:bg-[#161618] text-[#ededed] transition-colors"
                >
                  <span>Branch Name</span>
                  <span className={visibleColumns.branch ? 'text-emerald-400' : 'text-[#3f3f46]'}>
                    {visibleColumns.branch ? <CheckIcon /> : '—'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setVisibleColumns((c) => ({ ...c, vulnSummary: !c.vulnSummary }))}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono hover:bg-[#161618] text-[#ededed] transition-colors"
                >
                  <span>Vulnerability Summary</span>
                  <span className={visibleColumns.vulnSummary ? 'text-emerald-400' : 'text-[#3f3f46]'}>
                    {visibleColumns.vulnSummary ? <CheckIcon /> : '—'}
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setVisibleColumns((c) => ({ ...c, scanTime: !c.scanTime }))}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono hover:bg-[#161618] text-[#ededed] transition-colors"
                >
                  <span>Scan Duration & Time</span>
                  <span className={visibleColumns.scanTime ? 'text-emerald-400' : 'text-[#3f3f46]'}>
                    {visibleColumns.scanTime ? <CheckIcon /> : '—'}
                  </span>
                </button>
              </div>
            )}
          </div>

          {/* Export CSV Button */}
          <button
            type="button"
            onClick={handleExportCSV}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed] text-xs font-mono transition-colors"
          >
            <DownloadIcon />
            <span>Export CSV</span>
          </button>

          {/* New Audit Navigation */}
          <Link
            to="/audit/new"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#ededed] text-black hover:bg-white text-xs font-mono font-medium transition-all shadow-sm"
          >
            <PlusIcon />
            <span>New Audit</span>
          </Link>
        </div>
      </div>

      {/* ============================================================ */}
      {/*  2. Metrics Strip                                             */}
      {/* ============================================================ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 lg:gap-6 mb-6 sm:mb-8">
        {dynamicMetrics.map((m) => (
          <div
            key={m.label}
            className="bg-[#0a0a0a] rounded-xl p-4 border border-[#1e1e22] flex flex-col justify-between shadow-sm"
          >
            {/* Top row */}
            <div className="flex items-center justify-between text-[#71717a]">
              <span className="text-[10px] font-mono uppercase tracking-wider">
                {m.label}
              </span>
              <span className="flex items-center justify-center">{m.icon}</span>
            </div>

            {/* Value */}
            <div className="flex items-baseline gap-2 mt-3">
              <span className={`text-2xl font-semibold ${m.valueColor ?? 'text-white'}`}>
                {m.value}
                {m.valueSuffix && (
                  <span className="text-sm font-normal text-[#52525b]">
                    {m.valueSuffix}
                  </span>
                )}
              </span>
              {m.badge && (
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold ${m.badgeBg} ${m.badgeColor}`}
                >
                  {m.badge}
                </span>
              )}
              {m.sub && (
                <span className={`text-[11px] font-mono ${m.subColor}`}>
                  {m.sub}
                </span>
              )}
            </div>

            {/* Progress bar */}
            <div className="w-full bg-[#1e1e22] h-1 rounded-full mt-3 overflow-hidden">
              <div
                className={`${m.barColor} h-full rounded-full transition-all duration-700`}
                style={{ width: m.barWidth }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* ============================================================ */}
      {/*  3. Search & Filter Bar                                       */}
      {/* ============================================================ */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between mb-6">
        {/* Search */}
        <div className="flex-1 relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[#52525b] pointer-events-none">
            <SearchIcon />
          </span>
          <input
            ref={searchInputRef}
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-[#0a0a0a] border border-[#1e1e22] placeholder:text-[#52525b] text-[#ededed] text-xs font-mono pl-9 pr-24 py-2.5 rounded-lg outline-none focus:border-[#3f3f46] transition-colors"
            placeholder="Search projects by domain, repository, or CVE..."
            type="text"
          />
          {searchQuery ? (
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setCurrentPage(1);
              }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono text-[#71717a] hover:text-white p-1 rounded bg-[#1e1e22] transition-colors"
              title="Clear search"
            >
              <XIcon className="w-3 h-3" />
            </button>
          ) : (
            <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none">
              <kbd className="px-1.5 py-0.5 text-[10px] font-mono text-[#52525b] bg-[#1e1e22] rounded">
                ⌘
              </kbd>
              <kbd className="px-1.5 py-0.5 text-[10px] font-mono text-[#52525b] bg-[#1e1e22] rounded">
                K
              </kbd>
            </div>
          )}
        </div>

        {/* Filter & sort */}
        <div className="flex flex-wrap items-center gap-2 max-w-full">
          {/* Severity tabs */}
          <div className="flex items-center gap-1 bg-[#0a0a0a] border border-[#1e1e22] p-1 rounded-lg overflow-x-auto max-w-full" data-testid="severity-tabs">
            {(['All', 'Critical', 'High', 'Medium', 'Low'] as SeverityFilter[]).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => {
                  setSeverityFilter(sev);
                  setCurrentPage(1);
                }}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                  severityFilter === sev
                    ? 'bg-[#1e1e22] text-white shadow-sm font-medium'
                    : 'text-[#71717a] hover:text-[#ededed]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Grade tabs */}
          <div className="flex items-center gap-1 bg-[#0a0a0a] border border-[#1e1e22] p-1 rounded-lg overflow-x-auto max-w-full">
            {(['All', 'Grade A', 'Grade B', 'Grade C/D'] as GradeFilter[]).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => {
                  setActiveFilter(f);
                  setCurrentPage(1);
                }}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                  activeFilter === f
                    ? 'bg-[#1e1e22] text-white shadow-sm font-medium'
                    : 'text-[#71717a] hover:text-[#ededed]'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          {/* Env dropdown */}
          <div className="relative" ref={envRef}>
            <button
              type="button"
              onClick={() => {
                setShowEnvMenu((prev) => !prev);
                setShowColumnsMenu(false);
                setShowSortMenu(false);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0a0a0a] border border-[#1e1e22] hover:bg-[#111113] text-[#71717a] hover:text-[#ededed] text-[11px] font-mono transition-colors"
            >
              <span>Env: {envFilter}</span>
              <ChevronDown />
            </button>

            {showEnvMenu && (
              <div className="absolute left-0 sm:left-auto sm:right-0 mt-2 w-48 max-w-[calc(100vw-2rem)] rounded-xl bg-[#0a0a0a] border border-[#27272a] shadow-2xl p-1.5 z-40 flex flex-col gap-0.5">
                {(['All', 'Prod & Staging', 'Prod', 'Staging'] as EnvFilter[]).map((env) => (
                  <button
                    key={env}
                    type="button"
                    onClick={() => {
                      setEnvFilter(env);
                      setShowEnvMenu(false);
                      setCurrentPage(1);
                    }}
                    className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                      envFilter === env ? 'bg-[#1e1e22] text-white' : 'text-[#71717a] hover:bg-[#161618] hover:text-[#ededed]'
                    }`}
                  >
                    <span>{env === 'All' ? 'All Environments' : env === 'Prod & Staging' ? 'Prod & Staging' : `${env} Only`}</span>
                    {envFilter === env && <span className="text-emerald-400"><CheckIcon /></span>}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Sort dropdown */}
          <div className="relative" ref={sortRef}>
            <button
              type="button"
              onClick={() => {
                setShowSortMenu((prev) => !prev);
                setShowColumnsMenu(false);
                setShowEnvMenu(false);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0a0a0a] border border-[#1e1e22] hover:bg-[#111113] text-[#71717a] hover:text-[#ededed] text-[11px] font-mono transition-colors"
            >
              <span>
                Sort:{' '}
                {sortOption === 'recent'
                  ? 'Recent Scan'
                  : sortOption === 'score_desc'
                    ? 'Score: High-Low'
                    : sortOption === 'score_asc'
                      ? 'Score: Low-High'
                      : sortOption === 'vulns'
                        ? 'Most Criticals'
                        : 'Name: A-Z'}
              </span>
              <SortIcon />
            </button>

            {showSortMenu && (
              <div className="absolute right-0 mt-2 w-52 max-w-[calc(100vw-2rem)] rounded-xl bg-[#0a0a0a] border border-[#27272a] shadow-2xl p-1.5 z-40 flex flex-col gap-0.5">
                {[
                  { id: 'recent', label: 'Recent Scan' },
                  { id: 'score_desc', label: 'Health Score: High to Low' },
                  { id: 'score_asc', label: 'Health Score: Low to High' },
                  { id: 'vulns', label: 'Most Critical Issues' },
                  { id: 'name', label: 'Project Name (A–Z)' },
                ].map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => {
                      setSortOption(s.id as SortOption);
                      setShowSortMenu(false);
                      setCurrentPage(1);
                    }}
                    className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                      sortOption === s.id ? 'bg-[#1e1e22] text-white' : 'text-[#71717a] hover:bg-[#161618] hover:text-[#ededed]'
                    }`}
                  >
                    <span>{s.label}</span>
                    {sortOption === s.id && <span className="text-emerald-400"><CheckIcon /></span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/*  4. Project List & Bulk Selection                             */}
      {/* ============================================================ */}
      {/* Selection & Batch Action Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3 px-3.5 py-2.5 rounded-xl bg-[#0a0a0a] border border-[#1e1e22]">
        <div className="flex items-center gap-3">
          {/* Select all in current page checkbox */}
          <button
            type="button"
            onClick={toggleSelectAllCurrentPage}
            className={`w-4 h-4 rounded border flex items-center justify-center transition-all ${
              isAllCurrentPageSelected
                ? 'bg-white border-white text-black'
                : isSomeCurrentPageSelected
                ? 'bg-[#1e1e22] border-[#3f3f46] text-white'
                : 'border-[#3f3f46] bg-[#111113] hover:border-[#71717a]'
            }`}
            title={isAllCurrentPageSelected ? 'Deselect all on this page' : 'Select all on this page'}
          >
            {isAllCurrentPageSelected ? (
              <svg className="w-3 h-3 stroke-[3]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            ) : isSomeCurrentPageSelected ? (
              <div className="w-2 h-0.5 bg-white rounded-full" />
            ) : null}
          </button>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[#a1a1aa]">
              {selectedIds.length > 0 ? (
                <>
                  <strong className="text-white font-semibold">{selectedIds.length}</strong> of {filteredProjects.length} audits selected
                </>
              ) : (
                'Select audits for bulk actions'
              )}
            </span>

            {selectedIds.length > 0 && selectedIds.length < filteredProjects.length && (
              <button
                type="button"
                onClick={selectAllFiltered}
                className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 ml-1"
              >
                (Select all {filteredProjects.length} items)
              </button>
            )}
          </div>
        </div>

        {selectedIds.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={clearSelection}
              className="px-2.5 py-1 rounded-lg text-xs font-mono text-[#71717a] hover:text-[#ededed] hover:bg-[#161618] transition-colors"
            >
              Clear Selection
            </button>
            <button
              type="button"
              onClick={() => setShowBatchDeleteModal(true)}
              className="px-3 py-1 rounded-lg text-xs font-mono font-medium bg-red-600 hover:bg-red-500 text-white transition-colors flex items-center gap-1.5 shadow-sm"
            >
              <TrashIcon />
              <span>Delete ({selectedIds.length}) Selected</span>
            </button>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-3 mb-6">
        {paginatedProjects.map((p) => {
          const pKey = p.id || p.name;
          const isSelected = selectedIds.includes(pKey);
          return (
            <div
              key={pKey}
              className={`p-5 rounded-xl border transition-all duration-150 flex flex-col md:flex-row md:items-center justify-between gap-5 group ${
                isSelected
                  ? 'bg-[#111116] border-[#3b82f6]/40 shadow-sm shadow-[#3b82f6]/5'
                  : 'bg-[#0a0a0a] hover:bg-[#111113] border-[#1e1e22]'
              }`}
            >
              {/* Left section */}
              <div className="flex items-start gap-3.5 sm:gap-4 min-w-0">
                {/* Selection Checkbox */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleSelectOne(pKey);
                  }}
                  className={`w-4 h-4 rounded border flex items-center justify-center transition-all shrink-0 mt-3 sm:mt-2.5 ${
                    isSelected
                      ? 'bg-white border-white text-black'
                      : 'border-[#3f3f46] bg-[#111113] hover:border-[#71717a]'
                  }`}
                  title={isSelected ? 'Deselect this audit session' : 'Select this audit session'}
                >
                  {isSelected && (
                    <svg className="w-3 h-3 stroke-[3]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  )}
                </button>

                {/* Icon */}
                <div
                  className={`w-10 h-10 rounded-lg ${p.iconBg} flex items-center justify-center shrink-0 mt-0.5`}
                >
                  <span className={p.iconColor}>{renderProjectIcon(p.iconType, 'w-4 h-4')}</span>
                </div>

                <div className="flex flex-col min-w-0">
                  {/* Project name + badges */}
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="text-sm font-medium text-white truncate max-w-sm sm:max-w-md">
                      {p.name}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full ${p.gradeBg} ${p.gradeColor} text-[10px] font-mono font-semibold`}
                    >
                      {p.gradeLabel}
                    </span>
                    {visibleColumns.badges && (
                      <span className="px-2 py-0.5 rounded-full bg-[#1e1e22] text-[#a1a1aa] text-[10px] font-mono">
                        {p.auditType}
                      </span>
                    )}
                    {visibleColumns.badges && (p.grade === 'D' || p.grade === 'F') && (
                      <span className="px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 text-[10px] font-mono">
                        OWASP: {p.criticalCount ? `${p.criticalCount} Crit` : 'High Risk'}
                      </span>
                    )}
                  </div>

                  {/* Meta row */}
                  <div className="flex flex-wrap items-center gap-3 mt-1.5 text-[#71717a]">
                    {visibleColumns.repo && (
                      <span className="font-mono text-[11px] flex items-center gap-1 truncate max-w-xs">
                        <CodeIcon />
                        <span className="truncate">{p.repo}</span>
                      </span>
                    )}
                    {visibleColumns.repo && visibleColumns.branch && (
                      <span className="text-[#3f3f46]">·</span>
                    )}
                    {visibleColumns.branch && (
                      <span className="text-[11px] font-mono flex items-center gap-1">
                        <BranchIcon />
                        branch: {p.branch}
                      </span>
                    )}
                    {visibleColumns.vulnSummary && (
                      <>
                        <span className="text-[#3f3f46]">·</span>
                        <span className={`text-[11px] font-mono ${p.vulnColor}`}>
                          {p.vulnSummary}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Right section */}
              <div className="flex flex-col sm:flex-row md:flex-col items-start sm:items-center md:items-end justify-between md:justify-center gap-2.5 sm:gap-3 shrink-0 pt-3 md:pt-0 border-t md:border-t-0 border-[#1e1e22]/50 w-full md:w-auto">
                {/* Time info */}
                {visibleColumns.scanTime && (
                  <div className="flex items-center gap-2 text-[#71717a] text-[11px] font-mono">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${p.dotColor} ${p.dotPing ? 'animate-pulse' : ''}`}
                    />
                    <span>{p.timeAgo}</span>
                    <span className="text-[#3f3f46]">·</span>
                    <span>{p.scanDuration}</span>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto justify-start sm:justify-end">
                  <Link
                    to={p.id ? `/audit/progress/${p.id}` : `/audit/progress/${encodeURIComponent(p.name)}`}
                    className="px-2.5 py-1.5 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] text-[#ededed] text-[11px] font-mono transition-colors flex items-center gap-1"
                    title="Re-run pipeline audit"
                  >
                    <ReplayIcon />
                    <span>Re-run</span>
                  </Link>
                  <Link
                    to={p.id ? `/audit/report/${p.id}` : `/audit/report/${encodeURIComponent(p.name)}`}
                    className="px-3 py-1.5 rounded-lg bg-[#1e1e22] hover:bg-[#2a2a2e] text-[#ededed] text-[11px] font-mono transition-colors flex items-center gap-1"
                    title="View Security Report & AI Fixes"
                  >
                    <span>View Report</span>
                    <ChevronRight />
                  </Link>
                  {/* Delete Button */}
                  <button
                    type="button"
                    onClick={() => setProjectToDelete(p)}
                    className="p-1.5 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-red-500/10 hover:border-red-500/30 text-[#71717a] hover:text-red-400 transition-colors"
                    title="Delete this audit session"
                  >
                    <TrashIcon />
                  </button>
                </div>
              </div>
            </div>
          );
        })}

        {loading && (
          <div className="text-center py-16 px-4 bg-[#0a0a0a] rounded-xl border border-[#1e1e22] flex flex-col items-center justify-center gap-3">
            <div className="w-5 h-5 border-2 border-[#3f3f46] border-t-white rounded-full animate-spin" />
            <p className="text-xs text-[#71717a] font-mono">Loading user audit telemetry...</p>
          </div>
        )}

        {!loading && projectList.length === 0 && (
          <div className="text-center py-16 px-4 bg-[#0a0a0a] rounded-xl border border-[#1e1e22] flex flex-col items-center justify-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-[#111113] border border-[#1e1e22] flex items-center justify-center text-[#ededed] mb-1">
              <ShieldIcon className="w-6 h-6 text-[#ededed]" />
            </div>
            <p className="text-base text-[#ededed] font-medium">No Security Audits Yet</p>
            <p className="text-xs text-[#71717a] font-mono max-w-md">
              Your security workspace is ready. Launch an autonomous audit against your target URL or GitHub repository to analyze vulnerabilities, posture score, and automated patches.
            </p>
            <Link
              to="/audit/new"
              className="mt-2 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-white text-black text-xs font-medium hover:bg-[#ededed] transition-colors"
            >
              <PlusIcon className="w-3.5 h-3.5" />
              <span>Launch First Audit</span>
            </Link>
          </div>
        )}

        {!loading && projectList.length > 0 && filteredProjects.length === 0 && (
          <div className="text-center py-14 px-4 bg-[#0a0a0a] rounded-xl border border-[#1e1e22] flex flex-col items-center justify-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-[#111113] border border-[#1e1e22] flex items-center justify-center text-[#71717a] mb-1">
              <SearchEmptyIcon className="w-5 h-5" />
            </div>
            <p className="text-sm text-[#ededed] font-medium">No matching audit projects found</p>
            <p className="text-xs text-[#71717a] font-mono max-w-sm">
              Try adjusting your search query, posture grade filter ({activeFilter}), or environment filter ({envFilter}).
            </p>
          </div>
        )}
      </div>

      {/* ============================================================ */}
      {/*  5. Pagination & Custom Rows Selector                         */}
      {/* ============================================================ */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 py-3 text-[#71717a] text-[11px] font-mono border-t border-[#1e1e22] pt-4">
        <div className="flex flex-wrap items-center gap-3">
          <span>
            Showing{' '}
            <strong className="text-white font-medium">
              {filteredProjects.length === 0 ? 0 : `${startIndex + 1}–${Math.min(startIndex + itemsPerPage, filteredProjects.length)}`}
            </strong>{' '}
            of <strong className="text-white font-medium">{filteredProjects.length}</strong> monitored repositories
          </span>

          <span className="text-[#3f3f46]">·</span>

          {/* Items Per Page Selector */}
          <div className="flex items-center gap-1.5" ref={rowsRef}>
            <span>Show:</span>
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowRowsDropdown(!showRowsDropdown)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#111113] border border-[#1e1e22] hover:bg-[#161618] hover:border-[#27272a] text-[#ededed] text-xs font-mono transition-colors"
                title="Set number of rows per page"
              >
                <span>{itemsPerPage} data</span>
                <ChevronDown />
              </button>

              {showRowsDropdown && (
                <div className="absolute left-0 bottom-full mb-1 w-36 rounded-xl bg-[#0a0a0a] border border-[#27272a] shadow-2xl p-1.5 z-40 flex flex-col gap-0.5">
                  <span className="text-[10px] text-[#71717a] px-2 py-1 uppercase tracking-wider font-semibold">
                    Rows Per Page
                  </span>
                  {[5, 10, 20, 50, 100].map((num) => (
                    <button
                      key={num}
                      type="button"
                      onClick={() => {
                        setItemsPerPage(num);
                        setCustomRowsInput(String(num));
                        setShowRowsDropdown(false);
                        setCurrentPage(1);
                      }}
                      className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                        itemsPerPage === num
                          ? 'bg-[#1e1e22] text-white font-medium'
                          : 'text-[#71717a] hover:bg-[#161618] hover:text-[#ededed]'
                      }`}
                    >
                      <span>{num} data</span>
                      {itemsPerPage === num && <span className="text-emerald-400"><CheckIcon /></span>}
                    </button>
                  ))}

                  <div className="pt-1.5 mt-1 border-t border-[#1e1e22] px-1.5 pb-1">
                    <span className="text-[10px] text-[#71717a] block mb-1">Custom:</span>
                    <div className="flex items-center gap-1">
                      <input
                        type="number"
                        min="1"
                        max="500"
                        value={customRowsInput}
                        onChange={(e) => setCustomRowsInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = Math.max(1, parseInt(customRowsInput, 10) || 10);
                            setItemsPerPage(val);
                            setShowRowsDropdown(false);
                            setCurrentPage(1);
                          }
                        }}
                        className="w-16 bg-[#161618] border border-[#27272a] rounded px-1.5 py-1 text-xs text-white font-mono outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          const val = Math.max(1, parseInt(customRowsInput, 10) || 10);
                          setItemsPerPage(val);
                          setShowRowsDropdown(false);
                          setCurrentPage(1);
                        }}
                        className="px-2 py-1 bg-[#1e1e22] hover:bg-[#27272a] text-[#ededed] rounded text-[11px] font-mono transition-colors"
                      >
                        Set
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto max-w-full py-1">
          <button
            type="button"
            disabled={currentSafePage <= 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            className={`px-3 py-1.5 rounded bg-[#0a0a0a] border border-[#1e1e22] transition-colors text-[11px] font-mono ${
              currentSafePage <= 1 ? 'text-[#3f3f46] cursor-not-allowed' : 'text-[#ededed] hover:bg-[#111113]'
            }`}
          >
            Previous
          </button>

          {getPaginationNumbers().map((item, idx) => {
            if (item === '...') {
              return (
                <span key={`dots-${idx}`} className="w-7 h-7 flex items-center justify-center text-[#52525b] text-[11px] font-mono">
                  ...
                </span>
              );
            }
            const pageNum = item as number;
            return (
              <button
                key={pageNum}
                type="button"
                onClick={() => setCurrentPage(pageNum)}
                className={`w-7 h-7 rounded text-[11px] font-mono transition-colors flex items-center justify-center ${
                  currentSafePage === pageNum
                    ? 'bg-[#1e1e22] text-white font-semibold border border-[#3f3f46]'
                    : 'text-[#71717a] hover:text-white hover:bg-[#111113]'
                }`}
              >
                {pageNum}
              </button>
            );
          })}

          <button
            type="button"
            disabled={currentSafePage >= totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            className={`px-3 py-1.5 rounded bg-[#111113] border border-[#1e1e22] transition-colors text-[11px] font-mono ${
              currentSafePage >= totalPages ? 'text-[#3f3f46] cursor-not-allowed' : 'text-[#ededed] hover:bg-[#161618]'
            }`}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
