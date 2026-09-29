import React, { useState, useEffect, useMemo } from 'react';
import {
  UserAccount,
  IngestedNode,
  VerificationItem,
  MappingPack,
  AccessRequest,
  getSavedVerifications,
  saveVerifications,
  getSavedAiSettings,
  saveAiSettings,
  getSavedAccessRequests,
  saveAccessRequests,
  saveUsers,
  saveNodes,
} from './data/inv4rState';
import {
  api,
  ApiError,
  setToken,
  getToken,
  nodeFromBackend,
  applyNodeDetail,
  controlsFromAssess,
  fetchAssess,
  fetchSessions,
  endSession,
  startNewSession,
  fetchNodes,
  fetchReviewQueue,
  fetchReviewStatus,
  dismissReview,
  decideReview,
  fetchInvariants,
  verifyInvariant,
  summarizeAssessDevice,
  packFromBackend,
  titleCaseVendor,
  fetchFrameworkDetail,
  addFrameworkControl,
  fetchNodeDetail,
} from './data/api';
import type { BackendFrameworkDetail, ControlDefinitionInput, FrameworkSummary } from './data/api';
import { NewAuditFlow } from './components/NewAuditFlow';
import { SectionInfo } from './components/SectionInfo';
import { EvidencePanel, type EvidenceControl } from './components/EvidencePanel';
import { TrainingQueue } from './components/TrainingQueue';
import { severityTone, resultTone, bandTone } from './data/severity';
import {
  DEFAULT_FRAMEWORK,
  controlsFor,
  controlsParam,
  loadPolicySelection,
  policyLabel,
  savePolicySelection,
  selectedFrameworks,
  type PolicySelection,
} from './data/policy';

// Framework data always comes from the backend (/api/frameworks). Nothing about
// a policy — its name, version, or control count — is hardcoded in the UI.

const ICONS = {
  grid: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.6"/>
    </svg>
  ),
  play: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  ),
  upload: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><path d="M17 8l-5-5-5 5M12 3v12"/>
    </svg>
  ),
  server: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <rect x="3.2" y="4" width="17.6" height="6.8" rx="2"/><rect x="3.2" y="13.2" width="17.6" height="6.8" rx="2"/><path d="M7.2 7.4h.01M7.2 16.6h.01"/>
    </svg>
  ),
  shield: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M12 3l7.5 3v6c0 4.6-3.1 8-7.5 9.5C7.6 20 4.5 16.6 4.5 12V6L12 3z"/><path d="M9 12l2.2 2.2L15.5 10"/>
    </svg>
  ),
  layers: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M12 3l8.5 4.8L12 12.6 3.5 7.8 12 3z"/><path d="M3.5 12.2L12 17l8.5-4.8"/><path d="M3.5 16.4L12 21.2l8.5-4.8"/>
    </svg>
  ),
  file: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M14 3H7.5A2 2 0 005.5 5v14a2 2 0 002 2h9a2 2 0 002-2V8L14 3z"/><path d="M14 3v5h4.5M9 13h6M9 17h4"/>
    </svg>
  ),
  activity: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M3 12h3.5l2.5-7 4 14 2.5-7H21"/>
    </svg>
  ),
  flask: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M9 3h6v5.5l5 9.5a2 2 0 01-1.8 3H5.8a2 2 0 01-1.8-3l5-9.5V3z"/><path d="M7 14h10"/>
    </svg>
  ),
  brain: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="12" cy="12" r="3.2"/><path d="M12 3.5a4 4 0 00-4 4v.6a3.6 3.6 0 00-2 6.4 3.6 3.6 0 004 3.5 4 4 0 008 0 3.6 3.6 0 004-3.5 3.6 3.6 0 00-2-6.4V7.5a4 4 0 00-4-4 4 4 0 00-4 0z"/>
    </svg>
  ),
  git: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="12" r="2.5"/><path d="M6 8.5v7M8.5 6H15a3 3 0 013 3v.5"/>
    </svg>
  ),
  users: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="9.2" cy="8" r="3.2"/><path d="M3 20.2a6.2 6.2 0 0112.4 0"/><path d="M16.4 5.4a3.2 3.2 0 010 6.4M21 20.2a6.2 6.2 0 00-4.2-5.8"/>
    </svg>
  ),
  settings: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.9-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1A1.7 1.7 0 008.9 19a1.7 1.7 0 00-1.9.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.9 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1A1.7 1.7 0 004.6 9a1.7 1.7 0 00-.3-1.9l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.9.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1A1.7 1.7 0 0015 4.6a1.7 1.7 0 001.9-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.9V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>
    </svg>
  ),
  book: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M4 4.5A2.5 2.5 0 016.5 2H20v18H6.5A2.5 2.5 0 004 22.5v-18z"/><path d="M4 17.5A2.5 2.5 0 016.5 15H20"/>
    </svg>
  ),
  info: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v5h1"/>
    </svg>
  ),
  sun: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6"/>
    </svg>
  ),
  moon: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M20.5 14.6A8.6 8.6 0 019.4 3.5a8.6 8.6 0 1011.1 11.1z"/>
    </svg>
  ),
  sidebar: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/>
    </svg>
  ),
  refresh: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="w-[17px] h-[17px]">
      <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
    </svg>
  ),
};

interface NavItem {
  id: string;
  text: string;
  icon: keyof typeof ICONS;
}

interface NavGroup {
  label: string | null;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: null,
    items: [
      { id: 'dashboard', text: 'Dashboard', icon: 'grid' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { id: 'sessions', text: 'Sessions', icon: 'upload' },
      { id: 'nodes', text: 'Devices', icon: 'server' },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { id: 'controls', text: 'Controls', icon: 'shield' },
      { id: 'frameworks', text: 'Frameworks', icon: 'layers' },
      { id: 'reports', text: 'Reports', icon: 'file' },
    ],
  },
  {
    label: 'Security',
    items: [
      { id: 'verification', text: 'Behavioral Verification', icon: 'activity' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { id: 'training', text: 'Knowledge & Learning', icon: 'brain' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { id: 'users', text: 'Users', icon: 'users' },
    ],
  },
];

function EmptyState({ title, hint, actionLabel, onUpload }: {
  title: string;
  hint: string;
  actionLabel?: string;
  onUpload: () => void;
}) {
  return (
    <div className="card text-center py-12">
      <div className="w-12 h-12 mx-auto rounded-full bg-blue-900/20 text-blue-500 flex items-center justify-center text-xl font-bold mb-3">▤</div>
      <h2>{title}</h2>
      <p className="text-xs text-[var(--muted)] max-w-md mx-auto mb-4">{hint}</p>
      <button onClick={onUpload} className="btn primary">{actionLabel || 'Upload a configuration'}</button>
    </div>
  );
}

export default function App() {
  const [currentUser, setCurrentUser] = useState<UserAccount | null>(() => {
    try {
      const saved = localStorage.getItem('inv4r.currentUser');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');

  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isSubmittingLogin, setIsSubmittingLogin] = useState(false);

  const [showContactModal, setShowContactModal] = useState(false);
  const [copiedEmail, setCopiedEmail] = useState(false);

  const [reqFullName, setReqFullName] = useState('');
  const [reqEmail, setReqEmail] = useState('');
  const [reqRole, setReqRole] = useState<'Analyst' | 'Reviewer' | 'Admin'>('Analyst');
  const [reqJustification, setReqJustification] = useState('');
  const [reqPassword, setReqPassword] = useState('');
  const [requestSubmitted, setRequestSubmitted] = useState(false);

  const [currentView, setCurrentView] = useState(() => {
    const saved = localStorage.getItem('inv4r.currentView') || '';
    const known = new Set(NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id)));
    return known.has(saved) ? saved : 'dashboard';
  });
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);

  const [users, setUsers] = useState<UserAccount[]>([]);
  const [nodes, setNodes] = useState<IngestedNode[]>([]);
  const [verifications, setVerifications] = useState<VerificationItem[]>(getSavedVerifications);
  const [mappings, setMappings] = useState<MappingPack[]>([]);
  const [aiSettings, setAiSettings] = useState(getSavedAiSettings);
  const [aiLearnedExamples, setAiLearnedExamples] = useState(0);
  const [accessRequests, setAccessRequests] = useState<AccessRequest[]>(getSavedAccessRequests);

  const [frameworks, setFrameworks] = useState<FrameworkSummary[]>([]);
  const fwList = frameworks;
  const [frameworkStats, setFrameworkStats] = useState<Record<string, any>>({});
  const [showAllNodes, setShowAllNodes] = useState(false);
  const [sessions, setSessions] = useState<any[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string>('');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [sessionNodes, setSessionNodes] = useState<IngestedNode[]>([]);
  const [endingSession, setEndingSession] = useState(false);
  const [reviewQueue, setReviewQueue] = useState<{
    items: any[]; total: number; unresolved: number;
    categories: Record<string, number>; resolved: number;
    backlog: number; scope: string; session_id: string;
  } | null>(null);
  const [selectedReviewKeys, setSelectedReviewKeys] = useState<string[]>([]);
  const [reviewBusy, setReviewBusy] = useState(false);
  // Review counts and the report gate are scoped; decisions stay global.
  const [reviewScope, setReviewScope] = useState<'session' | 'all'>(() => {
    return localStorage.getItem('inv4r.reviewScope') === 'all' ? 'all' : 'session';
  });
  const [newSessionPrompt, setNewSessionPrompt] = useState<{ pending: number } | null>(null);
  const [startingSession, setStartingSession] = useState(false);
  const [invariants, setInvariants] = useState<any[]>([]);
  const [selectedInvariantId, setSelectedInvariantId] = useState<string>('');
  const [verifyRunning, setVerifyRunning] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [controlResultFilter, setControlResultFilter] = useState<string>('FAIL_UNKNOWN');
  const [controlSeverityFilter, setControlSeverityFilter] = useState<string>('ALL');
  const [controlSearch, setControlSearch] = useState('');
  const [reviewStatus, setReviewStatus] = useState<{ needs_review: boolean; outstanding: number; nodes?: any[]; backlog?: number; session_id?: string } | null>(null);
  const [cloudKeyConfigured, setCloudKeyConfigured] = useState(false);
  const [cloudKeyMasked, setCloudKeyMasked] = useState('');
  const [cloudProvider, setCloudProvider] = useState('openai');
  const [cloudKeyInput, setCloudKeyInput] = useState('');
  const [cloudKeySaving, setCloudKeySaving] = useState(false);
  const [aiSaving, setAiSaving] = useState(false);

  const [newUserName, setNewUserName] = useState('');
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserRole, setNewUserRole] = useState<'Admin' | 'Reviewer' | 'Analyst'>('Analyst');
  const [newUserPassword, setNewUserPassword] = useState('');

  // One policy selection drives every view and the backend evaluation. The
  // legacy single-framework keys are migrated by loadPolicySelection().
  const [policy, setPolicy] = useState<PolicySelection>(loadPolicySelection);
  const updatePolicy = (patch: Partial<PolicySelection>) => {
    setPolicy((prev) => {
      const next = { ...prev, ...patch };
      savePolicySelection(next);
      return next;
    });
  };
  const activeFrameworks = useMemo(() => selectedFrameworks(policy), [policy]);
  // Primary framework: used for upload session metadata and single-value labels.
  const selectedFramework = activeFrameworks[0] || DEFAULT_FRAMEWORK;
  const selectedFrameworkLabel = useMemo(() => {
    const fw = fwList.find((f) => f.profile_id === selectedFramework);
    return policyLabel(fw, selectedFramework);
  }, [fwList, selectedFramework]);
  const selectedControlsParam = useMemo(() => controlsParam(policy), [policy]);
  const assessScope = policy.scope;
  const setAssessScope = (scope: 'session' | 'uploaded' | 'all') => updatePolicy({ scope });

  const [frameworkDetail, setFrameworkDetail] = useState<BackendFrameworkDetail | null>(null);
  const [frameworkDetailLoading, setFrameworkDetailLoading] = useState(false);
  const [showAddControl, setShowAddControl] = useState(false);
  const [newControlId, setNewControlId] = useState('');
  const [newControlTitle, setNewControlTitle] = useState('');
  const [newControlFact, setNewControlFact] = useState('');
  const [newControlSeverity, setNewControlSeverity] = useState('medium');
  const [newControlExpect, setNewControlExpect] = useState('ABSENT');
  const [evidenceControl, setEvidenceControl] = useState<EvidenceControl | null>(null);
  const [evidenceRaw, setEvidenceRaw] = useState('');
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidencePreview, setEvidencePreview] = useState(false);
  const [reEvalNotice, setReEvalNotice] = useState<string | null>(null);
  const [lastUploadedName, setLastUploadedName] = useState<string | null>(() => {
    return localStorage.getItem('inv4r.lastUploaded');
  });
  const [scopedAssessment, setScopedAssessment] = useState<any>(null);
  // Provisional assessment computed with PENDING_REVIEW mapping packs. It never
  // overwrites the authoritative result; the UI shows both when they differ.
  const [previewAssessment, setPreviewAssessment] = useState<any>(null);
  const [assessLoading, setAssessLoading] = useState(false);

  const [activeDrawer, setActiveDrawer] = useState<{
    type: 'node' | 'training' | 'verification';
    data: any;
  } | null>(null);

  const accessibleNavGroups = useMemo(() => {
    return NAV_GROUPS.map((group) => {
      if (group.label === 'Admin') {
        return {
          ...group,
          items: group.items.filter((item) => {
            if (item.id === 'users') {
              return currentUser?.role === 'Admin';
            }
            return true;
          }),
        };
      }
      return group;
    });
  }, [currentUser?.role]);

  useEffect(() => {
    const savedTheme = localStorage.getItem('inv4r.theme') as 'light' | 'dark' | null;
    const pref = savedTheme || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(pref);
    document.documentElement.dataset.theme = pref;

    const savedCollapsed = localStorage.getItem('inv4r.collapsed') === '1';
    setIsCollapsed(savedCollapsed);
  }, []);

  const showToast = (text: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToastMessage({ text, type });
    setTimeout(() => setToastMessage(null), 3500);
  };

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.dataset.theme = next;
    localStorage.setItem('inv4r.theme', next);
  };

  const toggleCollapsed = () => {
    const next = !isCollapsed;
    setIsCollapsed(next);
    localStorage.setItem('inv4r.collapsed', next ? '1' : '0');
  };

  const handleLogin = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsSubmittingLogin(true);
    setLoginError(null);

    (async () => {
      try {
        const d = await api.post('/api/auth/login', {
          email: loginEmail.trim(),
          password: loginPassword.trim(),
        });
        if (d.token) setToken(d.token);
        const u: UserAccount = {
          email: d.user.email,
          name: d.user.name,
          role: d.user.role,
          createdAt: new Date().toISOString(),
        };
        setCurrentUser(u);
        localStorage.setItem('inv4r.currentUser', JSON.stringify(u));
        await loadServerData();
        setIsSubmittingLogin(false);
        showToast(`Welcome back, ${u.name}!`, 'success');
      } catch (err: any) {
        setIsSubmittingLogin(false);
        setLoginError(err?.message || 'Invalid credentials. Please verify your email and password.');
      }
    })();
  };

  const handleLogout = () => {
    api.post('/api/auth/logout', {}).catch(() => {});
    setToken('');
    setCurrentUser(null);
    setNodes([]);
    setUsers([]);
    setMappings([]);
    localStorage.removeItem('inv4r.currentUser');
    showToast('Signed out of INV4R', 'info');
  };

  const refreshSessions = async (): Promise<string> => {
    try {
      const d = await fetchSessions();
      setSessions(d.sessions || []);
      setCurrentSessionId(d.current_session_id || '');
      return d.current_session_id || '';
    } catch { return ''; /* sessions are best-effort */ }
  };

  // The review scope follows the "This session / All sessions" toggle on the
  // Knowledge & Learning page. Decisions themselves are always global.
  const reviewScopeSessionId = reviewScope === 'session' && currentSessionId ? currentSessionId : null;

  // ``sessionOverride`` lets a caller that just learned the current session id
  // (e.g. right after an upload) refresh the queue without waiting for the
  // session state to settle — otherwise the first upload of a session can
  // refresh against the previous session's scope and look empty.
  const refreshReviewQueue = async (sessionOverride?: string) => {
    const scopedSession = sessionOverride !== undefined
      ? (reviewScope === 'session' && sessionOverride ? sessionOverride : null)
      : reviewScopeSessionId;
    try {
      setReviewQueue(await fetchReviewQueue(scopedSession));
    } catch { /* queue refresh is best-effort */ }
  };

  // Per-framework aggregate counts for the Compliance Overview. Only the
  // SELECTED frameworks are queried, each with its own control subset, so an
  // unselected framework is never evaluated for the dashboard either.
  const refreshFrameworkStats = async () => {
    const ids = selectedFrameworks(policy);
    const queryFor = (profileId: string) => {
      const params = new URLSearchParams({ frameworks: profileId });
      // Qualified per framework, so a subset on one framework never narrows another.
      const subset = controlsParam(policy);
      if (subset) params.set('controls', subset);
      if (assessScope === 'session' && currentSessionId) params.set('session_id', currentSessionId);
      else if (assessScope === 'uploaded' && lastUploadedNodeId) params.set('node_id', lastUploadedNodeId);
      return params.toString();
    };
    const entries = await Promise.all(ids.map(async (id) => {
      try {
        return [id, await api.get(`/api/assess?${queryFor(id)}`)];
      } catch {
        return [id, null];
      }
    }));
    setFrameworkStats(Object.fromEntries(entries));
  };

  const loadServerData = async () => {
    try {
      const [nodesRes, usersRes, mappingsRes, fwRes] = await Promise.all([
        api.get('/api/nodes'),
        api.get('/api/auth/users').catch(() => ({ users: [] })),
        api.get('/api/mappings'),
        api.get('/api/frameworks'),
      ]);
      setNodes((nodesRes.nodes || []).map(nodeFromBackend));
      if (usersRes.users?.length) {
        setUsers(usersRes.users.map((u: any) => ({
          email: u.email, name: u.name, role: u.role, createdAt: '',
        })));
      }
      setMappings((mappingsRes.packs || []).map(packFromBackend));
      // Policy data is server-owned; the overview stats are refreshed by
      // refreshFrameworkStats() from the shared selection.
      if (fwRes.frameworks?.length) setFrameworks(fwRes.frameworks);
      fetchReviewStatus().then(setReviewStatus).catch(() => setReviewStatus(null));
      refreshSessions();
      refreshReviewQueue();
      fetchInvariants().then((d) => {
        setInvariants(d.invariants || []);
        setSelectedInvariantId((cur) => cur || d.invariants?.[0]?.id || '');
      }).catch(() => {});
      api.get('/api/ai').then((d: any) => {
        setCloudKeyConfigured(!!d.cloud_key?.configured);
        setCloudKeyMasked(d.cloud_key?.masked || '');
        if (d.cloud_key?.provider) setCloudProvider(d.cloud_key.provider);
        if (d.settings) setAiSettings({ mode: d.settings.mode, air_gapped: d.settings.air_gapped });
      }).catch(() => {});
      api.get('/api/status').then((st: any) => setAiLearnedExamples(st.learned_examples ?? 0)).catch(() => {});
    } catch (err: any) {
      showToast(err?.message || 'Failed to load fleet data', 'error');
    }
  };

  // Re-read the scoped review counts whenever the scope or session changes.
  useEffect(() => {
    if (!currentUser || !getToken()) return;
    refreshReviewStatus();
    refreshReviewQueue();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reviewScope, currentSessionId]);

  useEffect(() => {
    if (!currentUser || !getToken()) return;
    api.get('/api/auth/me')
      .then(() => loadServerData())
      .catch(() => {
        setToken('');
        setCurrentUser(null);
        localStorage.removeItem('inv4r.currentUser');
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRequestAccessSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reqEmail.trim() || !reqFullName.trim()) {
      showToast('Full name and email are required', 'error');
      return;
    }
    const newReq: AccessRequest = {
      id: `req-${Date.now()}`,
      name: reqFullName.trim(),
      email: reqEmail.trim(),
      requestedRole: reqRole,
      justification: reqJustification.trim() || 'Access for network compliance audit',
      submittedAt: new Date().toISOString(),
      status: 'PENDING',
    };
    const updated = [newReq, ...accessRequests];
    setAccessRequests(updated);
    saveAccessRequests(updated);
    setRequestSubmitted(true);
    showToast('Request sent to admin for review', 'success');
  };

  const handleApproveAccessRequest = (reqId: string, role?: 'Admin' | 'Reviewer' | 'Analyst') => {
    const req = accessRequests.find((r) => r.id === reqId);
    if (!req) return;
    const userRole = role || req.requestedRole || 'Analyst';

    if (!users.some((u) => u.email.toLowerCase() === req.email.toLowerCase())) {
      const newUser: UserAccount = {
        email: req.email,
        name: req.name,
        role: userRole,
        password: 'admin',
        createdAt: new Date().toISOString(),
      };
      const updatedUsers = [newUser, ...users];
      setUsers(updatedUsers);
      saveUsers(updatedUsers);
    }

    const updatedReqs = accessRequests.map((r) => (r.id === reqId ? { ...r, status: 'APPROVED' as const } : r));
    setAccessRequests(updatedReqs);
    saveAccessRequests(updatedReqs);
    showToast(`Approved access for ${req.name}. Account activated!`, 'success');
  };

  const handleRejectAccessRequest = (reqId: string) => {
    const updatedReqs = accessRequests.map((r) => (r.id === reqId ? { ...r, status: 'REJECTED' as const } : r));
    setAccessRequests(updatedReqs);
    saveAccessRequests(updatedReqs);
    showToast('Access request rejected', 'info');
  };

  const handleCreateUser = (newUser: { email: string; name: string; role: 'Admin' | 'Reviewer' | 'Analyst'; password?: string }) => {
    if (!newUser.email || !newUser.password) {
      showToast('Email and password are required', 'error');
      return;
    }
    if (users.some((u) => u.email.toLowerCase() === newUser.email.toLowerCase())) {
      showToast(`User ${newUser.email} already exists`, 'error');
      return;
    }
    api.post('/api/auth/users', {
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
      password: newUser.password,
    }).then(() => {
      const created: UserAccount = { ...newUser, createdAt: new Date().toISOString() };
      const updated = [created, ...users];
      setUsers(updated);
      saveUsers(updated);
      showToast(`User ${newUser.name || newUser.email} created successfully`, 'success');
    }).catch((err: any) => {
      showToast(err?.message || 'Failed to create user', 'error');
    });
  };

  const handleAddUserSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserEmail.trim() || !newUserName.trim() || !newUserPassword.trim()) {
      showToast('All fields (Name, Email, Role, Password) are required', 'error');
      return;
    }
    handleCreateUser({
      email: newUserEmail.trim(),
      name: newUserName.trim(),
      role: newUserRole,
      password: newUserPassword.trim(),
    });
    setNewUserName('');
    setNewUserEmail('');
    setNewUserPassword('');
  };

  const handleDeleteUser = (email: string) => {
    if (email === 'admin@inv4r.io' || email === 'admin') {
      showToast('Cannot delete primary Administrator account', 'error');
      return;
    }
    api.post('/api/auth/delete-user', { email }).then(() => {
      const updated = users.filter((u) => u.email !== email);
      setUsers(updated);
      saveUsers(updated);
      showToast(`User ${email} deleted`, 'info');
    }).catch((err: any) => {
      showToast(err?.message || 'Failed to delete user', 'error');
    });
  };

  const processConfigFile = async (filename: string, content: string) => {
    try {
      const form = new FormData();
      form.append('files', new File([content], filename, { type: 'text/plain' }));
      const d = await api.post('/api/upload', form);

      const res = (d.results || [])[0];
      if (!res) throw new Error('engine returned no result');
      if (res.status === 'error') throw new Error(res.error || 'processing failed');

      const detail = await fetchNodeDetail(res.filename || filename, {
        frameworks: activeFrameworks, controls: selectedControlsParam,
      });
      let node: IngestedNode = nodeFromBackend({
        id: res.filename || filename,
        name: res.filename || filename,
        path: '', vendor: res.vendor, platform: res.platform, adapter: res.adapter,
        tier: res.tier, facts_count: res.facts_count, unknown_count: res.unknown_count,
        coverage_level: res.coverage_level, coverage_name: res.coverage_name,
        compliance_score: 0, compliance_band: 'unknown',
        file_size: 0, evidence_id: res.evidence_id, sha256: '', duplicate: !!res.duplicate,
      });
      node = applyNodeDetail(node, detail);

      const existing = nodes.filter((n) => n.id !== node.id);
      const updatedNodes = [node, ...existing];
      setNodes(updatedNodes);
      saveNodes(updatedNodes);
      setLastUploadedName(node.id);
      localStorage.setItem('inv4r.lastUploaded', node.id);
      updatePolicy({ scope: 'session' });
      refreshSessions();
      refreshReviewQueue();
      refreshReviewStatus();
      showToast(
        `Ingested ${node.name}: ${titleCaseVendor(res.vendor)} · ${res.facts_count} facts · ${res.coverage_name || 'normalized'}` +
        (res.duplicate ? ' (duplicate of existing evidence)' : ''),
        res.duplicate ? 'info' : 'success'
      );
    } catch (err: any) {
      showToast(`${filename}: ${err?.message || 'upload failed'}`, 'error');
    }
  };

  const handleFilesUploaded = async (files: FileList | File[] | null, framework = selectedFramework): Promise<IngestedNode[]> => {
    if (!files || files.length === 0) return [];
      try {
        const arr = Array.from(files);
        const form = new FormData();
        arr.forEach((f) => form.append('files', f, f.name));
        const d = await api.post('/api/upload', form);
        const results: any[] = d.results || [];

        const processed: IngestedNode[] = [];
        for (const res of results) {
          if (res.status === 'error') {
            showToast(`${res.filename || 'file'}: ${res.error || 'processing failed'}`, 'error');
            continue;
          }
          try {
            const detail = await fetchNodeDetail(res.filename, {
              frameworks: activeFrameworks, controls: selectedControlsParam,
            });
            let node: IngestedNode = nodeFromBackend({
              id: res.filename, name: res.filename, path: '',
              vendor: res.vendor, platform: res.platform, adapter: res.adapter,
              tier: res.tier, facts_count: res.facts_count, unknown_count: res.unknown_count,
              coverage_level: res.coverage_level, coverage_name: res.coverage_name,
              compliance_score: 0, compliance_band: 'unknown',
              file_size: 0, evidence_id: res.evidence_id, sha256: '', duplicate: !!res.duplicate,
            });
            node = applyNodeDetail(node, detail);
            processed.push(node);
          } catch {  }
        }

        if (processed.length) {
          const ids = new Set(processed.map((n) => n.id));
          const updatedNodes = [...processed, ...nodes.filter((n) => !ids.has(n.id))];
          setNodes(updatedNodes);
          saveNodes(updatedNodes);
          setLastUploadedName(processed[0].id);
          localStorage.setItem('inv4r.lastUploaded', processed[0].id);
          updatePolicy({ scope: 'session' });
          // Refresh the queue against the session this upload actually landed
          // in, so the newly discovered unknowns are listed immediately.
          refreshSessions().then((sid) => refreshReviewQueue(sid));
          refreshReviewStatus();
          return processed;
        }
        const ok = results.filter((r) => r.status === 'ok').length;
        showToast(`${ok} of ${d.total} file(s) ingested by the INV4R engine` + (d.duplicates ? ` · ${d.duplicates} duplicate(s)` : ''), ok ? 'success' : 'error');
        return processed;
      } catch (err: any) {
        showToast(err?.message || 'Upload failed', 'error');
        return [];
      }
  };

  const handleRunVerification = async (scope: string) => {
    showToast('Executing behavioral verification via the INV4R engine…', 'info');
    try {
      const sit = await api.post('/api/behaviour/situation', {
        session_id: scope === 'session' && currentSessionId ? currentSessionId : null,
      });
      const checks: any[] = sit.checks || [];
      const now = new Date().toISOString();
      const newItems: VerificationItem[] = checks.map((c, i) => ({
        verification_id: `ver-${Date.now()}-${i}`,
        node_id: 'fleet',
        control_id: c.type || 'INVARIANT',
        control_title: c.summary || c.type || 'Invariant',
        severity: 'HIGH' as const,
        audit_result: (c.status === 'PASS' ? 'PASS' : c.status === 'FAIL' ? 'FAIL' : 'UNKNOWN') as 'PASS' | 'FAIL' | 'UNKNOWN',
        expected_behavior: 'ALLOWED' as const,
        batfish_result: sit.batfish_available === false ? undefined : { result: c.status, detail: c.summary || '' },
        correlation: (c.status === 'PASS' ? 'VERIFIED_PASS' : c.status === 'FAIL' ? 'VERIFIED_FAIL' : 'INCONCLUSIVE') as any,
        execution_status: sit.batfish_available === false ? 'SKIPPED_BATFISH_UNAVAILABLE' : 'COMPLETED',
        created_at: now,
      }));
      const updated = [...newItems, ...verifications].slice(0, 50);
      setVerifications(updated);
      saveVerifications(updated);
      if (!sit.batfish_available) {
        showToast('Batfish unavailable — engine situation checks only (start the batfish container for full path verification)', 'info');
      } else {
        showToast(`Verification completed: ${checks.length} engine checks evaluated`, 'success');
      }
    } catch (err: any) {
      showToast(err?.message || 'Verification failed', 'error');
    }
  };

  const handleClassifyVerification = (id: string, classification: any, reason: string) => {
    const updated = verifications.map((v) => {
      if (v.verification_id === id) {
        return {
          ...v,
          review: {
            classification,
            reason,
            reviewer: currentUser?.name || 'Administrator',
            reviewed_at: new Date().toISOString(),
          },
        };
      }
      return v;
    });
    setVerifications(updated);
    saveVerifications(updated);
    setActiveDrawer(null);
    showToast('Classification saved and committed to audit trail', 'success');
  };

  const refreshTrainingNode = async (nodeId: string) => {
    try {
      const [sess, detail] = await Promise.all([
        api.get(`/api/train/session/${encodeURIComponent(nodeId)}`),
        api.get(`/api/nodes/${encodeURIComponent(nodeId)}`),
      ]);
      let node = nodes.find((n) => n.id === nodeId);
      if (!node) {
        const listRes = await api.get('/api/nodes');
        const entry = (listRes.nodes || []).find((x: any) => x.id === nodeId);
        if (entry) node = nodeFromBackend(entry);
      }
      if (!node) return null;
      const merged = applyNodeDetail(node, detail);
      const sessPending = (sess.pending || []).map((p: any) => ({
        proposal_id: p.proposal_id, raw_path: p.raw_path, raw_text: p.raw_text,
        category: p.category, suggested_fact: p.suggested_fact ?? undefined,
        suggestion_confidence: p.suggestion_confidence, suggested_by: p.suggested_by,
      }));
      merged.unknown_fragments = sessPending;
      merged.unknown_count = sessPending.length;
      const updatedNodes = nodes.map((n) => (n.id === nodeId ? merged : n));
      setNodes(updatedNodes);
      saveNodes(updatedNodes);
      return merged;
    } catch {
      return null;
    }
  };

  const handleDecideFragment = (nodeId: string, proposalId: string, decision: 'APPROVED' | 'REJECTED', factName?: string) => {
    (async () => {
      try {
        const body: any = { node_id: nodeId, proposal_id: proposalId, decision };
        if (factName && decision === 'APPROVED') body.fact = factName;
        await api.post('/api/train/decide', body);
        if (decision === 'APPROVED') {
          showToast(`Fragment mapped to "${factName}" and committed to the mapping ledger`, 'success');
        } else {
          showToast('Fragment rejected', 'info');
        }
      } catch (err: any) {
        showToast(err?.message || 'Decision failed', 'error');
      }
      const merged = await refreshTrainingNode(nodeId);
      if (activeDrawer?.type === 'training' && merged) {
        setActiveDrawer({ type: 'training', data: merged });
      }
      // A trained mapping must re-evaluate the affected configuration without
      // the user re-running the workflow.
      await refreshEvaluations();
    })();
  };

  const handleApproveMappingPack = (mapId: string) => {
    api.post('/api/mappings/approve', { map_id: mapId }).then(() => {
      const updated = mappings.map((p) => (p.map_id === mapId ? { ...p, status: 'ACTIVE' as const } : p));
      setMappings(updated);
      showToast(`Mapping Pack ${mapId} approved — the authoritative result now updates`, 'success');
      refreshEvaluations();
    }).catch((err: any) => showToast(err?.message || 'Approval failed', 'error'));
  };

  const handleRejectMappingPack = (mapId: string) => {
    api.post('/api/mappings/reject', { map_id: mapId }).then(() => {
      const updated = mappings.map((p) => (p.map_id === mapId ? { ...p, status: 'REJECTED' as const } : p));
      setMappings(updated);
      showToast(`Mapping Pack ${mapId} rejected`, 'info');
    }).catch((err: any) => showToast(err?.message || 'Rejection failed', 'error'));
  };

  const openNodeDrawer = (node: IngestedNode) => {
    setActiveDrawer({ type: 'node', data: node });
    if ((node as any).__detailLoaded) return;
    fetchNodeDetail(node.id, { frameworks: activeFrameworks, controls: selectedControlsParam })
      .then((detail) => {
        const merged = applyNodeDetail(node, detail);
        setActiveDrawer({ type: 'node', data: merged });
        setNodes((prev) => {
          const updated = prev.map((n) => (n.id === merged.id ? merged : n));
          saveNodes(updated);
          return updated;
        });
      })
      .catch(() => {  });
  };

  const openTrainingDrawer = (node: IngestedNode) => {
    setActiveDrawer({ type: 'training', data: node });
    refreshTrainingNode(node.id).then((merged) => {
      if (merged) setActiveDrawer({ type: 'training', data: merged });
    });
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = async (preliminary = false) => {
    // The backend gate decides; it is scoped to the nodes in this report, so a
    // stale backlog from another session never blocks it client-side. A
    // preliminary download always works and marks itself as a draft.
    try {
      showToast(preliminary
        ? 'Generating preliminary Fleet PDF (draft — unresolved lines listed with suggestions)…'
        : 'Generating official Fleet Compliance PDF report…', 'info');
      const scopeParam = assessScope === 'session' && currentSessionId
        ? `&session_id=${encodeURIComponent(currentSessionId)}` : '';
      const blob = await api.blob(`/api/report/pdf/fleet?framework=${encodeURIComponent(selectedFramework)}${scopeParam}${preliminary ? '&preliminary=true' : ''}`);
      downloadBlob(blob, `inv4r-fleet-compliance-${selectedFramework}${preliminary ? '-preliminary' : ''}.pdf`);
      showToast(preliminary
        ? 'Preliminary Fleet PDF downloaded — not a final result'
        : 'Fleet Compliance PDF generated and downloaded successfully', 'success');
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 409) {
        refreshReviewStatus();
        showToast(`${err.message} Open the Review queue to resolve them, then retry.`, 'error');
      } else {
        showToast('PDF download failed: ' + (err?.message || String(err)), 'error');
      }
    }
  };

  const handleDownloadNodePdf = async (node: IngestedNode, preliminary = false) => {
    // No client-side pre-check: the backend gate counts only the unresolved
    // items that occur on THIS node, and a direct API call cannot bypass it —
    // except for the explicitly-marked preliminary draft.
    try {
      showToast(preliminary ? `Generating preliminary dossier for ${node.name}…`
        : `Generating PDF dossier for ${node.name}…`, 'info');
      const blob = await api.blob(
        `/api/report/pdf?node_id=${encodeURIComponent(node.id)}&framework=${encodeURIComponent(selectedFramework)}${preliminary ? '&preliminary=true' : ''}`,
      );
      downloadBlob(blob, `inv4r-node-dossier-${node.name}${preliminary ? '-preliminary' : ''}.pdf`);
      showToast(preliminary ? `Preliminary dossier for ${node.name} downloaded (draft)`
        : `Dossier for ${node.name} downloaded`, 'success');
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 409) {
        showToast(`${err.message} Open the Review queue to resolve them, then retry.`, 'error');
      } else {
        showToast('PDF error: ' + (err?.message || String(err)), 'error');
      }
    }
  };

  const refreshReviewStatus = () => {
    fetchReviewStatus(reviewScopeSessionId)
      .then(setReviewStatus)
      .catch(() => setReviewStatus(null));
  };

  const handleEndSession = async () => {
    setEndingSession(true);
    try {
      const d = await endSession();
      if (d.session) showToast(`Session ${d.session.id} closed — its device(s) were cleared. The next upload opens a new session.`, 'success');
      else showToast('No open session to close', 'info');
      await refreshSessions();
      // The closed session's devices were purged server-side; refresh so the
      // fleet views stop listing them immediately.
      await refreshEvaluations();
      refreshReviewQueue();
      refreshReviewStatus();
    } catch (err: any) {
      showToast(err?.message || 'Failed to end session', 'error');
    } finally {
      setEndingSession(false);
    }
  };

  // "New Session" resets the session VIEW only. Unresolved items stay in the
  // backlog and every approved decision / learned example is kept.
  const requestNewSession = () => {
    const pending = reviewStatus?.outstanding ?? 0;
    if (pending > 0) {
      setNewSessionPrompt({ pending });
      return;
    }
    void performNewSession();
  };

  const performNewSession = async () => {
    setStartingSession(true);
    try {
      const d = await startNewSession(selectedFramework);
      setNewSessionPrompt(null);
      setSelectedReviewKeys([]);
      await refreshSessions();
      updatePolicy({ scope: 'session' });
      setReviewScope('session');
      localStorage.setItem('inv4r.reviewScope', 'session');
      // The closing session's devices were cleared server-side: drop every
      // stale node/assessment state so no removed device lingers in the UI.
      await refreshEvaluations();
      refreshReviewQueue();
      refreshReviewStatus();
      showToast(`New session opened — ${d.nodes_cleared ?? 0} device(s) from the previous session were cleared. Learned mappings were not touched.`, 'success');
    } catch (err: any) {
      showToast(err?.message || 'Failed to start a new session', 'error');
    } finally {
      setStartingSession(false);
    }
  };

  const handleDismissBacklog = async (keys: string[]) => {
    if (!keys.length) return;
    setReviewBusy(true);
    try {
      const d = await dismissReview(keys);
      showToast(`${d.dismissed} backlog item(s) dismissed`, 'success');
      setSelectedReviewKeys([]);
      await refreshReviewQueue();
      refreshReviewStatus();
    } catch (err: any) {
      showToast(err?.message || 'Dismiss failed', 'error');
    } finally {
      setReviewBusy(false);
    }
  };

  const toggleReviewKey = (key: string) => {
    setSelectedReviewKeys((prev) => prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]);
  };

  // Re-run the affected evaluation immediately after a training decision or a
  // mapping-pack lifecycle change. The authoritative result stays authoritative
  // while a mapping is PENDING_REVIEW; the provisional preview predicts the
  // outcome until a reviewer promotes the pack to ACTIVE.
  const refreshEvaluations = async () => {
    try {
      const nodesRes = await api.get('/api/nodes');
      setNodes((nodesRes.nodes || []).map(nodeFromBackend));
    } catch { /* best-effort */ }
    const base = {
      frameworks: activeFrameworks,
      controls: selectedControlsParam,
      nodeId: assessScope === 'uploaded' ? lastUploadedNodeId || undefined : undefined,
      sessionId: assessScope === 'session' ? currentSessionId : undefined,
    };
    try { setScopedAssessment(await fetchAssess(base)); } catch { /* keep prior */ }
    try {
      const packsRes = await api.get('/api/mappings');
      const packs = packsRes.packs || [];
      setMappings(packs.map(packFromBackend));
      setPreviewAssessment(packs.some((p: any) => p.status === 'PENDING_REVIEW')
        ? await fetchAssess({ ...base, preview: true })
        : null);
    } catch { /* preview is best-effort */ }
    refreshFrameworkStats();
    setReEvalNotice('Evaluation refreshed from the latest training decisions.');
    setTimeout(() => setReEvalNotice(null), 6000);
  };

  // Returns the number of unique items applied so a caller (the audit flow)
  // can wait for the automatic re-evaluation before rendering final results.
  const runReviewDecisions = async (
    decisions: Array<{ key: string; decision: string; fact?: string }>,
  ): Promise<number> => {
    if (!decisions.length) return 0;
    setReviewBusy(true);
    try {
      const d = await decideReview(decisions);
      const approved = decisions.filter((x) => x.decision === 'APPROVED').length;
      showToast(
        `${d.applied} unique item(s) recorded (${approved} mapped) on ${d.nodes_updated} node(s) — re-evaluating`,
        'success',
      );
      setSelectedReviewKeys([]);
      await refreshReviewQueue();
      refreshReviewStatus();
      await refreshEvaluations();
      return d.applied ?? 0;
    } catch (err: any) {
      showToast(err?.message || 'Review decision failed', 'error');
      return 0;
    } finally {
      setReviewBusy(false);
    }
  };

  // The Evidence action is the only place a control's raw configuration and
  // remediation are shown, so it is fetched fresh for the selected policy.
  const openEvidence = async (control: any) => {
    // A preview row shows the provisional result until the pack is promoted, so
    // the evidence is fetched from the preview engine too.
    const isPreview = !!control?.preview_result;
    setEvidenceControl({ ...control, preview_result: isPreview });
    setEvidencePreview(isPreview);
    setEvidenceRaw('');
    const nodeName = control?.node;
    if (!nodeName) return;
    setEvidenceLoading(true);
    try {
      const d = await fetchNodeDetail(nodeName, {
        frameworks: activeFrameworks,
        controls: selectedControlsParam,
        preview: isPreview,
      });
      const fresh = (d.compliance?.controls || []).find(
        (c: any) => c.control_id === control.control_id,
      );
      if (fresh) {
        setEvidenceControl({
          ...control,
          severity: String(fresh.severity || control.severity).toUpperCase(),
          result: String(fresh.result || control.result).toUpperCase(),
          detail: fresh.detail || '',
          framework: fresh.framework || control.framework,
          evidence_lines: fresh.evidence_lines || [],
          remediation: fresh.remediation || '',
          remediation_cli_sequence: fresh.remediation_cli_sequence || [],
          has_remediation: !!fresh.has_remediation,
          expected: fresh.expected || '',
          observed: fresh.observed || '',
          reason: fresh.reason || '',
          preview_result: isPreview,
        });
      }
      setEvidenceRaw(d.raw_config || '');
    } catch {
      /* evidence falls back to whatever the control already carried */
    } finally {
      setEvidenceLoading(false);
    }
  };

  // --- Framework library: detail, checklist, and Admin Add-Control ---------
  const openFramework = async (profileId: string) => {
    setFrameworkDetailLoading(true);
    try {
      setFrameworkDetail(await fetchFrameworkDetail(profileId));
    } catch (err: any) {
      showToast(err?.message || 'Could not load framework', 'error');
    } finally {
      setFrameworkDetailLoading(false);
    }
  };

  const detailControlIds = (frameworkDetail?.controls || []).map((c) => c.control_id);
  const currentControlSelection: string[] | 'ALL' = frameworkDetail
    ? controlsFor(policy, frameworkDetail.profile_id)
    : 'ALL';
  const selectionSet = new Set(
    currentControlSelection === 'ALL' ? detailControlIds : currentControlSelection,
  );

  const setFrameworkSelection = (ids: string[]) => {
    if (!frameworkDetail) return;
    const isAll = ids.length === detailControlIds.length;
    updatePolicy({
      frameworks: activeFrameworks.includes(frameworkDetail.profile_id)
        ? activeFrameworks : [...activeFrameworks, frameworkDetail.profile_id],
      controls: { ...policy.controls, [frameworkDetail.profile_id]: isAll ? 'ALL' : ids },
    });
  };

  const toggleDetailControl = (controlId: string) => {
    const next = new Set(selectionSet);
    if (next.has(controlId)) next.delete(controlId); else next.add(controlId);
    setFrameworkSelection(Array.from(next));
  };

  const toggleFrameworkEvaluated = (profileId: string, on: boolean) => {
    const next = on
      ? Array.from(new Set([...activeFrameworks, profileId]))
      : activeFrameworks.filter((f) => f !== profileId);
    // Never leave the selection empty: a policy must always be evaluated.
    updatePolicy({ frameworks: next.length ? next : [profileId] });
  };

  const addControlToFramework = async (input: ControlDefinitionInput) => {
    if (!frameworkDetail) return;
    try {
      const d = await addFrameworkControl(frameworkDetail.profile_id, input);
      setFrameworkDetail(d);
      setShowAddControl(false);
      setNewControlId(''); setNewControlTitle(''); setNewControlFact('');
      showToast(`Control ${input.id} added to ${policyLabel(d)}`, 'success');
    } catch (err: any) {
      showToast(err?.message || 'Add control failed', 'error');
    }
  };

  const handleRunInvariant = async () => {
    if (!selectedInvariantId) return;
    setVerifyRunning(true);
    setVerifyResult(null);
    try {
      const res = await verifyInvariant(
        selectedInvariantId,
        assessScope === 'session' ? currentSessionId : null,
      );
      setVerifyResult(res);
      if (!res.batfish_available) {
        showToast('Batfish unavailable — the invariant result is UNKNOWN, not guessed', 'info');
      }
    } catch (err: any) {
      showToast(err?.message || 'Verification failed', 'error');
    } finally {
      setVerifyRunning(false);
    }
  };

  const handleSaveAiSettings = (next: { mode: string; air_gapped: boolean }) => {
    setAiSaving(true);
    api.post('/api/settings', next)
      .then((d: any) => {
        if (d.settings) {
          const saved = { mode: d.settings.mode, air_gapped: d.settings.air_gapped };
          setAiSettings(saved);
          saveAiSettings(saved);
        }
        showToast('AI engine settings saved on the server', 'success');
      })
      .catch((err: any) => showToast(err?.message || 'Save failed (admin role required)', 'error'))
      .finally(() => setAiSaving(false));
  };

  const chooseLane = (mode: string) => {
    setAiSettings((s) => ({ ...s, mode }));
    // Cloud LLM cannot be persisted until a key exists; show the key form first.
    if (mode === 'cloud_llm' && !cloudKeyConfigured) return;
    handleSaveAiSettings({ mode, air_gapped: aiSettings.air_gapped });
  };

  const handleSaveCloudKey = (e: React.FormEvent) => {
    e.preventDefault();
    const key = cloudKeyInput.trim();
    if (key.length < 8) {
      showToast('Enter a valid API key', 'error');
      return;
    }
    setCloudKeySaving(true);
    api.post('/api/ai/cloud-key', { key, provider: cloudProvider })
      .then((d: any) => {
        setCloudKeyConfigured(!!d.configured);
        setCloudKeyMasked(d.masked || '');
        setCloudKeyInput('');
        showToast('Cloud API key encrypted and stored', 'success');
        if (aiSettings.mode === 'cloud_llm') {
          handleSaveAiSettings({ mode: 'cloud_llm', air_gapped: aiSettings.air_gapped });
        }
      })
      .catch((err: any) => showToast(err?.message || 'Failed to store key', 'error'))
      .finally(() => setCloudKeySaving(false));
  };

  const handleRemoveCloudKey = () => {
    setCloudKeySaving(true);
    api.post('/api/ai/cloud-key/remove', {})
      .then(() => {
        setCloudKeyConfigured(false);
        setCloudKeyMasked('');
        setCloudKeyInput('');
        showToast('Stored cloud API key removed', 'info');
      })
      .catch((err: any) => showToast(err?.message || 'Failed to remove key', 'error'))
      .finally(() => setCloudKeySaving(false));
  };

  const allControlResults = useMemo(() => {
    return nodes.flatMap((n) => n.control_results);
  }, [nodes]);

  const lastUploadedNodeId = useMemo(() => {
    if (!lastUploadedName) return null;
    const match = nodes.find((n) => n.id === lastUploadedName || n.name === lastUploadedName);
    return match ? match.id : null;
  }, [nodes, lastUploadedName]);

  useEffect(() => {
    if (!currentUser || !getToken()) return;
    if (assessScope === 'uploaded' && !lastUploadedNodeId) {
      setScopedAssessment(null);
      return;
    }
    if (assessScope === 'session' && !currentSessionId) {
      setScopedAssessment(null);
      return;
    }
    let cancelled = false;
    setAssessLoading(true);
    const base = {
      frameworks: activeFrameworks,
      controls: selectedControlsParam,
      nodeId: assessScope === 'uploaded' ? lastUploadedNodeId || undefined : undefined,
      sessionId: assessScope === 'session' ? currentSessionId : undefined,
    };
    const hasPending = mappings.some((p) => p.status === 'PENDING_REVIEW');
    fetchAssess(base)
      .then((d: any) => { if (!cancelled) setScopedAssessment(d); })
      .catch(() => { if (!cancelled) setScopedAssessment(null); })
      .finally(() => { if (!cancelled) setAssessLoading(false); });
    if (hasPending) {
      fetchAssess({ ...base, preview: true })
        .then((d: any) => { if (!cancelled) setPreviewAssessment(d); })
        .catch(() => { if (!cancelled) setPreviewAssessment(null); });
    } else if (!cancelled) {
      setPreviewAssessment(null);
    }
    return () => { cancelled = true; };
  }, [currentUser, assessScope, activeFrameworks.join(','), selectedControlsParam,
      lastUploadedNodeId, currentSessionId, mappings.length]);

  useEffect(() => {
    if (!selectedSessionId) {
      setSessionNodes([]);
      return;
    }
    fetchNodes(selectedSessionId)
      .then((d) => setSessionNodes((d.nodes || []).map(nodeFromBackend)))
      .catch(() => setSessionNodes([]));
  }, [selectedSessionId]);

  useEffect(() => {
    if (!currentUser || !getToken()) return;
    refreshFrameworkStats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser, assessScope, currentSessionId, lastUploadedNodeId, activeFrameworks.join(','), selectedControlsParam]);

  const scopeDevices = useMemo(() => {
    if (!scopedAssessment?.devices?.length) return [];
    return scopedAssessment.devices.map(summarizeAssessDevice);
  }, [scopedAssessment]);

  const scopeControls = useMemo(() => {
    if (!scopedAssessment?.devices?.length) return [];
    const authoritative = controlsFromAssess(scopedAssessment.devices);
    const preview = controlsFromAssess(previewAssessment?.devices || []);
    if (!preview.length) return authoritative;
    const byKey = new Map(preview.map((c) => [`${c.control_id}|${c.node}`, c]));
    return authoritative.map((c) => {
      const p = byKey.get(`${c.control_id}|${c.node}`);
      return p && p.result !== c.result ? { ...c, preview_result: p.result } : c;
    });
  }, [scopedAssessment, previewAssessment]);

  const activeControls = scopeControls.length ? scopeControls : allControlResults;

  const filteredControls = useMemo(() => {
    const q = controlSearch.trim().toLowerCase();
    return scopeControls.filter((c) => {
      const result = String(c.result || '').toUpperCase();
      if (controlResultFilter === 'FAIL_UNKNOWN') {
        if (result !== 'FAIL' && result !== 'UNKNOWN') return false;
      } else if (controlResultFilter !== 'ALL' && result !== controlResultFilter) {
        return false;
      }
      if (controlSeverityFilter !== 'ALL'
          && String(c.severity || '').toUpperCase() !== controlSeverityFilter) {
        return false;
      }
      if (q && !String(c.node || '').toLowerCase().includes(q)) return false;
      return true;
    });
  }, [scopeControls, controlResultFilter, controlSeverityFilter, controlSearch]);

  const scopeScore = useMemo(() => {
    if (!scopeDevices.length) return null;
    return scopeDevices.reduce((s, d) => s + d.score, 0) / scopeDevices.length;
  }, [scopeDevices]);

  // The per-node card must honour the Scope filter too, not always show the
  // whole fleet.
  const dashboardNodeRows = useMemo(() => {
    if (assessScope === 'all' || scopeDevices.length === 0) return nodes;
    return scopeDevices.map((d) => {
      const full = nodes.find((n) => n.name === d.filename || n.id === d.filename);
      return {
        ...(full || {}),
        id: full?.id || d.filename,
        name: d.filename,
        vendor: full?.vendor || d.vendor,
        platform: full?.platform || d.platform,
        facts_count: d.facts_count,
        unknown_count: d.unknown_count,
        controls_evaluated: d.pass + d.fail,
        controls_total: d.pass + d.fail + d.unknown,
        compliance_score: d.score,
        compliance_band: d.band,
      };
    });
  }, [assessScope, scopeDevices, nodes]);

  const scopeSevCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, pass: 0, unknown: 0 };
    for (const c of scopeControls) {
      if (c.result === 'FAIL') {
        const sev = String(c.severity || '').toUpperCase();
        if (sev === 'CRITICAL') counts.critical += 1;
        else if (sev === 'HIGH') counts.high += 1;
        else if (sev === 'MEDIUM') counts.medium += 1;
        else counts.low += 1;
      } else if (c.result === 'PASS') {
        counts.pass += 1;
      } else if (c.result === 'UNKNOWN') {
        counts.unknown += 1;
      }
    }
    return counts;
  }, [scopeControls]);

  const categoryBars = useMemo(() => {
    const cb = scopedAssessment?.category_breakdown || {};
    return Object.entries(cb).map(([name, v]: [string, any]) => ({
      name,
      p: v?.PASS || 0, f: v?.FAIL || 0, u: v?.UNKNOWN || 0,
    }));
  }, [scopedAssessment]);

  const passCount = activeControls.filter((c) => c.result === 'PASS').length;
  const failCount = activeControls.filter((c) => c.result === 'FAIL').length;
  const unknownCount = activeControls.filter((c) => c.result === 'UNKNOWN').length;

  const activePacksCount = mappings.filter((p) => p.status === 'ACTIVE').length;
  const pendingPacksCount = mappings.filter((p) => p.status === 'PENDING_REVIEW').length;

  const applicableCount = passCount + failCount + unknownCount;

  // Top nodes by risk = lowest compliance score first; previewed until the
  // operator opts into the full per-node table.
  const topRiskNodes = useMemo(
    () => [...dashboardNodeRows]
      .sort((a, b) => (a.compliance_score ?? 0) - (b.compliance_score ?? 0))
      .slice(0, 5),
    [dashboardNodeRows],
  );

  const failingCategories = useMemo(
    () => categoryBars.filter((c) => c.f > 0).sort((a, b) => b.f - a.f),
    [categoryBars],
  );

  // Aggregated control results per SELECTED framework. The Compliance Overview
  // renders these as three explicitly labelled counts (Passed / Failed /
  // Unknown) — never individual controls, and never the risk score.
  const frameworkCards = useMemo(
    () => selectedFrameworks(policy).map((profileId) => {
      const fw = fwList.find((f) => f.profile_id === profileId) || {
        profile_id: profileId, title: profileId, framework: '', version: '',
        description: '', control_count: 0,
      } as FrameworkSummary;
      const summary = frameworkStats[profileId]?.summary || null;
      const passed = summary?.controls_passed ?? 0;
      const failed = summary?.controls_failed ?? 0;
      const unknown = summary?.controls_unknown ?? 0;
      const applicable = passed + failed + unknown;
      return {
        fw,
        summary,
        passed,
        failed,
        unknown,
        passRate: applicable ? Math.round((passed / applicable) * 100) : 0,
        evaluated: applicable,
        avgScore: summary?.avg_score ?? null,
        devices: summary?.devices ?? 0,
        hasData: summary != null,
      };
    }),
    [fwList, frameworkStats, policy],
  );

  // One bar per SELECTED framework — never a per-control-id bucket such as
  // "CIS 1.1". Each bar is three side-by-side columns (Pass / Fail / Unknown)
  // so a framework is read as one unit.
  const frameworkBars = useMemo(
    () => frameworkCards.map(({ fw, passed, failed, unknown, evaluated }) => ({
      name: policyLabel(fw, fw.profile_id),
      p: passed,
      f: failed,
      u: unknown,
      total: evaluated,
    })),
    [frameworkCards, fwList],
  );

  // Shared y-axis so column heights are comparable between frameworks.
  const chartMax = Math.max(1, ...frameworkBars.map((b) => Math.max(b.p, b.f, b.u)));

  if (!currentUser) {
    return (
      <div className="login-page">
        <button
          type="button"
          className="top-signin cursor-pointer hover:bg-[#3d2c94] transition-colors"
          onClick={() => {
            setAuthMode(authMode === 'login' ? 'register' : 'login');
            setRequestSubmitted(false);
            setLoginError(null);
          }}
        >
          {authMode === 'login' ? 'Sign In / Request Access' : 'Return to Login'}
        </button>

        <section className="left">
          <div className="left-content">
            <div className="welcome">Welcome back!</div>
            <h1>Good to see you<br />Again!</h1>

            <div className="feature">
              <div className="feature-icon">▥</div>
              <div>
                <strong>Analytics</strong>
                <span>Track real time performance</span>
              </div>
            </div>

            <div className="feature">
              <div className="feature-icon">♙</div>
              <div>
                <strong>Security</strong>
                <span>Enterprise grade protection</span>
              </div>
            </div>

            <div className="feature">
              <div className="feature-icon">ϟ</div>
              <div>
                <strong>Speed</strong>
                <span>Super fast and reliable</span>
              </div>
            </div>
          </div>
        </section>

        <section className="right">
          {authMode === 'login' ? (
            <div className="login-card">
              <div className="lock">♙</div>
              <h2>Login to your account</h2>
              <div className="subtitle">Enter your credentials to continue</div>

              {loginError && (
                <div className="mb-4 p-2.5 rounded bg-red-900/40 border border-red-500/50 text-xs text-red-200 font-semibold">
                  {loginError}
                </div>
              )}

              <form onSubmit={handleLogin}>
                <label className="login-label">Email or Username</label>
                <div className="input-wrap">
                  <span className="icon">✉</span>
                  <input
                    type="text"
                    className="login-input"
                    placeholder="Enter your username or email"
                    value={loginEmail}
                    onChange={(e) => setLoginEmail(e.target.value)}
                    required
                  />
                </div>

                <label className="login-label">Password</label>
                <div className="input-wrap">
                  <span className="icon">♙</span>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    className="login-input"
                    placeholder="Enter your password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    required
                  />
                  <span
                    className="eye"
                    onClick={() => setShowPassword(!showPassword)}
                    title="Toggle password view"
                  >
                    {showPassword ? '🐵' : '◉'}
                  </span>
                </div>

                <div className="options">
                  <label className="remember">
                    <input type="checkbox" defaultChecked /> Remember me
                  </label>
                  <a
                    href="#forgot"
                    onClick={(e) => {
                      e.preventDefault();
                      setShowContactModal(true);
                    }}
                  >
                    Forgot password?
                  </a>
                </div>

                <button type="submit" className="login-btn" disabled={isSubmittingLogin}>
                  {isSubmittingLogin ? 'Signing in…' : 'Continue'}
                </button>
              </form>

              <div className="divider">or</div>

              <button
                className="google"
                type="button"
                onClick={() => {
                  setLoginEmail('admin');
                  setLoginPassword('admin');
                  handleLogin();
                }}
              >
                <b>G</b> Continue with Enterprise Single Sign-On
              </button>

              <div className="help">
                Need help?{' '}
                <a
                  href="#contact"
                  onClick={(e) => {
                    e.preventDefault();
                    setShowContactModal(true);
                  }}
                >
                  Contact admin
                </a>
              </div>
            </div>
          ) : (

            <div className="login-card">
              <div className="lock">♙</div>
              <h2>Sign In / Request Access</h2>
              <div className="subtitle">Submit your details for platform onboarding</div>

              {requestSubmitted ? (
                <div className="p-5 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-center space-y-3">
                  <div className="w-10 h-10 mx-auto rounded-full bg-emerald-600/30 flex items-center justify-center text-emerald-400 text-lg font-bold">
                    ✓
                  </div>
                  <h3 className="text-base font-bold text-white">Sent to admin for review</h3>
                  <p className="text-xs text-emerald-200 leading-relaxed">
                    Your platform registration has been sent to the administrator for review. Once verified, your account will be activated and you can sign in.
                  </p>
                  <div className="text-[11px] text-slate-300 pt-1">
                    Primary Admin Contact:{' '}
                    <span className="font-mono text-emerald-300">admin-support@inv4r.corp</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('login');
                      setRequestSubmitted(false);
                    }}
                    className="login-btn mt-3"
                  >
                    Return to Login
                  </button>
                </div>
              ) : (
                <form onSubmit={handleRequestAccessSubmit}>
                  <label className="login-label">Full Name</label>
                  <div className="input-wrap">
                    <span className="icon">👤</span>
                    <input
                      type="text"
                      className="login-input"
                      placeholder="e.g. John Doe"
                      value={reqFullName}
                      onChange={(e) => setReqFullName(e.target.value)}
                      required
                    />
                  </div>

                  <label className="login-label">Work Email</label>
                  <div className="input-wrap">
                    <span className="icon">✉</span>
                    <input
                      type="email"
                      className="login-input"
                      placeholder="user@organization.corp"
                      value={reqEmail}
                      onChange={(e) => setReqEmail(e.target.value)}
                      required
                    />
                  </div>

                  <label className="login-label">Requested Role</label>
                  <div className="input-wrap">
                    <select
                      value={reqRole}
                      onChange={(e) => setReqRole(e.target.value as any)}
                      className="login-input bg-white text-slate-900 pr-4"
                    >
                      <option value="Analyst">Analyst (Auditing & Ingestion)</option>
                      <option value="Reviewer">Reviewer (HIL & Contradictions)</option>
                      <option value="Admin">Administrator (Full Access)</option>
                    </select>
                  </div>

                  <label className="login-label">Access Justification</label>
                  <div className="input-wrap">
                    <input
                      type="text"
                      className="login-input"
                      placeholder="e.g. Spine compliance verification"
                      value={reqJustification}
                      onChange={(e) => setReqJustification(e.target.value)}
                    />
                  </div>

                  <label className="login-label">Password</label>
                  <div className="input-wrap">
                    <span className="icon">♙</span>
                    <input
                      type="password"
                      className="login-input"
                      placeholder="Create account password"
                      value={reqPassword}
                      onChange={(e) => setReqPassword(e.target.value)}
                      required
                    />
                  </div>

                  <button type="submit" className="login-btn mt-4">
                    Submit Access Request
                  </button>

                  <div className="help text-center mt-3">
                    Already have credentials?{' '}
                    <a
                      href="#login"
                      onClick={(e) => {
                        e.preventDefault();
                        setAuthMode('login');
                      }}
                    >
                      Sign In here
                    </a>
                  </div>
                </form>
              )}
            </div>
          )}
        </section>

        {showContactModal && (
          <div className="modal-overlay" onClick={() => setShowContactModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center justify-between pb-3 border-b border-slate-700">
                <div className="flex items-center gap-2">
                  <span className="text-blue-400 text-lg">✉</span>
                  <h3 className="text-base font-bold text-white">Platform Administrator Contact</h3>
                </div>
                <button
                  onClick={() => setShowContactModal(false)}
                  className="text-slate-400 hover:text-white text-lg p-1"
                >
                  ✕
                </button>
              </div>

              <div className="py-4 space-y-4">
                <p className="text-xs text-slate-300">
                  For account recovery, role provisioning, or tenant onboarding, reach out to the designated system administrators:
                </p>

                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-700 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[11px] text-slate-400 font-semibold uppercase">Administrator Email</div>
                      <div className="font-mono text-sm text-blue-400 font-bold">admin-support@inv4r.corp</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText('admin-support@inv4r.corp');
                        setCopiedEmail(true);
                        setTimeout(() => setCopiedEmail(false), 2500);
                      }}
                      className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors"
                    >
                      {copiedEmail ? 'Copied!' : 'Copy Email'}
                    </button>
                  </div>

                  <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-300">
                    <span>Operations Desk:</span>
                    <span className="font-mono text-slate-200">secops-lead@inv4r.internal</span>
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-300">
                    <span>Emergency Hotline:</span>
                    <span className="font-mono text-slate-200">+1 (888) 555-0199</span>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400">
                  Response SLA: Standard access requests and password resets are processed within 1 business hour.
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-700">
                <a
                  href="mailto:admin-support@inv4r.corp?subject=INV4R%20Platform%20Access%20Request"
                  className="px-3.5 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors"
                >
                  Send Email
                </a>
                <button
                  type="button"
                  onClick={() => setShowContactModal(false)}
                  className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  const userInitials = (currentUser.name || currentUser.email || 'A')
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((x) => x[0].toUpperCase())
    .join('');

  const currentNavTitle =
    accessibleNavGroups.flatMap((g) => g.items).find((i) => i.id === currentView)?.text || (currentView === 'users' ? 'Users' : 'Dashboard');

  return (
    <div className="app-container">
      <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-header">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white font-extrabold text-sm shrink-0">
            IV
          </div>
          {!isCollapsed && <span className="brand-title">INV4R</span>}
        </div>

        <nav className="sidebar-nav">
          {accessibleNavGroups.map((group, gIdx) => (
            <div key={gIdx} className="mb-2">
              {!isCollapsed && group.label && <div className="nav-label">{group.label}</div>}
              {group.items.map((item) => {
                const isActive = currentView === item.id;
                return (
                  <div
                    key={item.id}
                    onClick={() => setCurrentView(item.id)}
                    className={`nav-item ${isActive ? 'active' : ''}`}
                    title={item.text}
                  >
                    <span className="shrink-0">{ICONS[item.icon]}</span>
                    {!isCollapsed && <span className="truncate">{item.text}</span>}
                  </div>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-user">
          <div className="user-avatar">{userInitials}</div>
          {!isCollapsed && (
            <div className="flex-1 min-w-0">
              <div className="text-[12.5px] font-semibold text-white truncate">{currentUser.name}</div>
              <div className="text-[11px] text-[var(--sbText)] truncate">{currentUser.role}</div>
            </div>
          )}
          <button
            onClick={handleLogout}
            title="Sign out"
            className="text-[var(--sbText)] hover:text-white transition-colors p-1"
          >
            ✕
          </button>
        </div>
      </aside>

      <div className={`main-wrapper ${isCollapsed ? 'collapsed' : ''}`}>
        <header className="topbar">
          <div className="flex items-center gap-3">
            <button
              onClick={toggleCollapsed}
              className="p-1.5 rounded-lg text-[var(--muted)] hover:bg-[var(--hover)] hover:text-[var(--text)] transition-colors"
              title="Toggle sidebar"
            >
              {ICONS.sidebar}
            </button>
            <h1 className="page-title">{currentNavTitle}</h1>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => showToast('Refreshed data state', 'info')}
              className="p-1.5 rounded-lg text-[var(--muted)] hover:bg-[var(--hover)] hover:text-[var(--text)] transition-colors"
              title="Refresh view"
            >
              {ICONS.refresh}
            </button>
            <button
              onClick={toggleTheme}
              className="p-1.5 rounded-lg text-[var(--muted)] hover:bg-[var(--hover)] hover:text-[var(--text)] transition-colors"
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {theme === 'dark' ? ICONS.sun : ICONS.moon}
            </button>
          </div>
        </header>

        <main className="content-body">
          {reEvalNotice && (
            <div
              className="card mb-3"
              style={{ borderColor: 'var(--green)', padding: '10px 14px' }}
              role="status"
            >
              <span className="text-xs">✓ {reEvalNotice}</span>
            </div>
          )}
          {currentView === 'dashboard' && (
            nodes.length === 0 ? (
              <EmptyState
                title="No devices yet"
                hint="Upload a configuration to get started — every dashboard number is computed from what you have actually ingested."
                onUpload={() => setCurrentView('upload')}
              />
            ) : (
            <>
              {reviewStatus?.needs_review && (
                <div className="card" style={{ borderColor: 'var(--amber)' }}>
                  <div className="card-h" style={{ marginBottom: 0 }}>
                    <div>
                      <h2 style={{ color: 'var(--amber)' }}>
                        Review required: {reviewStatus.outstanding} unique unresolved item(s) in {reviewScope === 'session' ? 'this session' : 'all sessions'}
                      </h2>
                      <p>Deduplicated by configuration line, not per-node occurrences. Reports stay gated until every item in this scope is reviewed.</p>
                      {(reviewStatus.backlog ?? 0) > 0 && (
                        <p className="small" style={{ marginTop: 4 }}>
                          {(reviewStatus.backlog ?? 0)} more in backlog from earlier sessions —{' '}
                          <button
                            style={{ textDecoration: 'underline' }}
                            onClick={() => {
                              setReviewScope('all');
                              localStorage.setItem('inv4r.reviewScope', 'all');
                              setCurrentView('training');
                            }}
                          >
                            review all sessions
                          </button>
                          {' '}· they do not block this session's report.
                        </p>
                      )}
                    </div>
                    <button onClick={() => setCurrentView('training')} className="btn primary">
                      Open review queue
                    </button>
                  </div>
                </div>
              )}
              <div className="card">
                <div className="card-h">
                  <div>
                    <p className="text-xs font-bold tracking-[0.12em] text-blue-600">NETWORK SECURITY POSTURE<SectionInfo id="compliance-overview" /></p>
                    <h2 className="mt-1 text-2xl">{scopeScore != null ? `${scopeScore.toFixed(1)} / 100` : '—'}</h2>
                    <p className="muted small">{assessLoading ? 'Evaluating…' : scopeDevices.length === 1 ? `Single config: ${scopeDevices[0].filename}` : `${scopeDevices.length} configs · framework: ${selectedFramework}`}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2">
                      <label className="text-xs muted">Scope</label>
                      <select
                        value={assessScope}
                        onChange={(e) => {
                          setAssessScope(e.target.value as 'session' | 'uploaded' | 'all');
                        }}
                        className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]"
                      >
                        <option value="session">Current session</option>
                        <option value="uploaded">Last uploaded config</option>
                        <option value="all">All nodes ({nodes.length})</option>
                      </select>
                    </div>
                    <button
                      onClick={requestNewSession}
                      disabled={startingSession}
                      className="btn"
                      title="Close the open session and start a fresh one. Learned mappings and past decisions are kept."
                    >
                      {startingSession ? 'Starting…' : 'New Session'}
                    </button>
                    <button onClick={() => setCurrentView('upload')} className="btn primary">+ New Audit</button>
                  </div>
                </div>
                <div className="grid grid-cols-6 gap-2 border-t border-[var(--line)] pt-4 text-center">
                  <div><b className="text-red-500">{scopeSevCounts.critical}</b><p className="small muted">Critical</p></div>
                  <div><b className="text-orange-500">{scopeSevCounts.high}</b><p className="small muted">High</p></div>
                  <div><b className="text-amber-500">{scopeSevCounts.medium}</b><p className="small muted">Medium</p></div>
                  <div><b className="text-blue-500">{scopeSevCounts.low}</b><p className="small muted">Low</p></div>
                  <div><b className="text-[var(--green)]">{scopeSevCounts.pass}</b><p className="small muted">Pass</p></div>
                  <div><b>{scopeSevCounts.unknown}</b><p className="small muted">Unknown</p></div>
                </div>
              </div>

              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Compliance Overview</h2>
                    <p>Pass rate and control counts from the latest assessment, per framework</p>
                  </div>
                  <SectionInfo id="frameworks" align="right" />
                </div>
                {frameworkCards.length === 0 ? (
                  <p className="muted small">
                    No policy selected. Open Frameworks to choose the policy to evaluate.
                  </p>
                ) : (
                  <div className="fw-grid">
                    {frameworkCards.map(({ fw, passed, failed, unknown, avgScore, hasData }) => (
                      <div
                        key={fw.profile_id}
                        className={`fw-card ${selectedFramework === fw.profile_id ? 'selected' : ''}`}
                        title={fw.description}
                      >
                        <div className="fw-head">
                          {/* Exact policy identifier + version from policy metadata. */}
                          <span className="fw-name">{policyLabel(fw)}</span>
                        </div>
                        <div className="fw-stats" style={{ marginTop: 12 }}>
                          <span className="fw-stat">
                            <b className="text-[var(--green)]" style={{ fontSize: 20 }}>{hasData ? passed : '—'}</b>
                            <span className="muted small">PASSED</span>
                          </span>
                          <span className="fw-stat">
                            <b className="text-red-500" style={{ fontSize: 20 }}>{hasData ? failed : '—'}</b>
                            <span className="muted small">FAILED</span>
                          </span>
                          <span className="fw-stat">
                            <b className="text-amber-500" style={{ fontSize: 20 }}>{hasData ? unknown : '—'}</b>
                            <span className="muted small">UNKNOWN</span>
                          </span>
                        </div>
                        <div className="fw-stats" style={{ marginTop: 10 }}>
                          <span className="fw-stat">Controls in policy <b>{fw.control_count}</b></span>
                          <span className="fw-stat">Avg score <b>{hasData && avgScore != null ? avgScore : '—'}</b></span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="row dash1">
                <div className="card">
                  <div className="card-h">
                    <div>
                      <h2>{failCount} Failed Control Tests<SectionInfo id="control-monitoring" /></h2>
                    </div>
                    <button onClick={() => setCurrentView('controls')} className="btn danger sm">
                      Review Failures
                    </button>
                  </div>

                  <div className="legend" style={{ marginBottom: 14 }}>
                    <span><i className="g"></i>Pass {passCount}</span>
                    <span><i className="r"></i>Fail {failCount}</span>
                    <span><i className="a"></i>Unknown {unknownCount}</span>
                  </div>

                  <div className="chart">
                    <div className="plot">
                      <div className="gridline" style={{ top: '0%' }}></div>
                      <div className="ylab" style={{ top: '0%' }}>{chartMax}</div>
                      <div className="gridline" style={{ top: '50%' }}></div>
                      <div className="ylab" style={{ top: '50%' }}>{Math.round(chartMax / 2)}</div>
                      <div className="gridline" style={{ top: '100%' }}></div>
                      <div className="ylab" style={{ top: '100%' }}>0</div>

                      <div className="bars">
                        {(frameworkBars.length
                          ? frameworkBars
                          : [{ name: 'No framework selected', p: 0, f: 0, u: 0, total: 0 }]
                        ).map((b) => (
                          <div
                            key={b.name}
                            className="bar-col"
                            title={`${b.name}: ${b.p} pass / ${b.f} fail / ${b.u} unknown of ${b.total} controls`}
                          >
                            <div className="bar g" style={{ height: `${(b.p / chartMax) * 100}%` }}>
                              {b.p > 0 && <span className="bnum">{b.p}</span>}
                            </div>
                            <div className="bar r" style={{ height: `${(b.f / chartMax) * 100}%` }}>
                              {b.f > 0 && <span className="bnum">{b.f}</span>}
                            </div>
                            <div className="bar a" style={{ height: `${(b.u / chartMax) * 100}%` }}>
                              {b.u > 0 && <span className="bnum">{b.u}</span>}
                            </div>
                            <div className="xlab">{b.name}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div style={{ height: 22 }}></div>

                  <div className="card-h" style={{ marginTop: 8, marginBottom: 6 }}>
                    <div>
                      <h2 style={{ fontSize: 14 }}>Failing Controls by Category</h2>
                    </div>
                  </div>
                  {failingCategories.length === 0 ? (
                    <p className="muted small">No failing controls in the current scope.</p>
                  ) : (
                    <div>
                      {failingCategories.map((c) => (
                        <div key={c.name} className="cat-row">
                          <span className="cat-name">{c.name}</span>
                          <span className="cat-count">{c.f} failing</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

              </div>

              {/* Minimal, non-duplicative operational metrics. AI/training state
                  (packs, learned examples, lane) lives in the ingest workflow,
                  not on the compliance dashboard. */}
              <div className="row metrics">
                <div className="tile">
                  <div className="t-ico b">{ICONS.server}</div>
                  <div className="t-num">{nodes.length}</div>
                  <div className="t-lbl">Nodes Ingested</div>
                </div>
                <div className="tile">
                  <div className="t-ico g">{ICONS.shield}</div>
                  <div className="t-num">{applicableCount}</div>
                  <div className="t-lbl">Controls Evaluated</div>
                </div>
              </div>

              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Per-Node Compliance<SectionInfo id="node-compliance" /></h2>
                    <p>Fleet summary with the highest-risk devices, or the full per-node table</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => setShowAllNodes((v) => !v)} className="btn sm">
                      {showAllNodes ? 'Show summary' : 'Show all nodes'}
                    </button>
                    <button onClick={() => setCurrentView('nodes')} className="btn sm">View Nodes</button>
                  </div>
                </div>

                <div className="fleet-stats" style={{ marginBottom: 16 }}>
                  <div className="fleet-stat"><b className="text-emerald-500">{passCount}</b><span>Passing</span></div>
                  <div className="fleet-stat"><b className="text-red-500">{failCount}</b><span>Failing</span></div>
                  <div className="fleet-stat"><b className="text-amber-500">{unknownCount}</b><span>Unknown</span></div>
                  <div className="fleet-stat"><b>{scopeScore != null ? scopeScore.toFixed(1) : '—'}</b><span>Avg risk score</span></div>
                </div>

                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>Node</th>
                        <th>Vendor</th>
                        <th>Platform</th>
                        <th>Facts</th>
                        <th>Unknown</th>
                        <th>Coverage</th>
                        <th>Score</th>
                        <th>Band</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(showAllNodes ? dashboardNodeRows : topRiskNodes).map((n) => (
                        <tr key={n.id} className="clickable" onClick={() => openNodeDrawer(n)}>
                          <td><b>{n.name}</b></td>
                          <td>{n.vendor}</td>
                          <td>{n.platform}</td>
                          <td>{n.facts_count}</td>
                          <td>{n.unknown_count}</td>
                          {/* Coverage reports controls evaluated/total (from the assessment); per-node remediation coverage is not exposed by the list endpoint. */}
                          <td>{`Controls Evaluated: ${n.controls_evaluated ?? 0}/${n.controls_total ?? 0}`}</td>
                          <td><b>{n.compliance_score.toFixed(1)}%</b></td>
                          <td>
                            <span className={`bdg ${bandTone(n.compliance_band)}`}>{n.compliance_band}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!showAllNodes && dashboardNodeRows.length > topRiskNodes.length && (
                  <p className="muted small" style={{ marginTop: 10 }}>
                    Showing the {topRiskNodes.length} highest-risk of {dashboardNodeRows.length} nodes in scope.
                  </p>
                )}
              </div>
            </>
            )
          )}

          {currentView === 'sessions' && (
            selectedSessionId ? (
              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Session {selectedSessionId}</h2>
                    <p>{sessionNodes.length} node(s) uploaded in this session</p>
                  </div>
                  <button onClick={() => setSelectedSessionId(null)} className="btn sm">Back to sessions</button>
                </div>
                {sessionNodes.length === 0 ? (
                  <p className="muted small">No nodes in this session.</p>
                ) : (
                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead><tr><th>Node</th><th>Vendor</th><th>IP Address</th><th>Serial</th><th>Score</th><th>Band</th><th></th></tr></thead>
                    <tbody>
                      {sessionNodes.map((n) => (
                        <tr key={n.id} className="clickable" onClick={() => openNodeDrawer(n)}>
                          <td><b>{n.name}</b></td>
                          <td>{n.vendor}</td>
                          <td className="mono text-xs">{n.ip_address || 'not provided'}</td>
                          <td className="mono text-xs">{n.serial || 'not provided'}</td>
                          <td><b>{n.compliance_score.toFixed(1)}%</b></td>
                          <td><span className={`bdg ${bandTone(n.compliance_band)}`}>{n.compliance_band}</span></td>
                          <td><button onClick={(e) => { e.stopPropagation(); openNodeDrawer(n); }} className="btn sm">Open</button></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                )}
              </div>
            ) : (
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Sessions</h2>
                  <p>Each upload groups its nodes into an assessment session. Scope the dashboard to a session to see only what was just uploaded.</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={requestNewSession} disabled={startingSession} className="btn sm">
                    {startingSession ? 'Starting…' : 'New Session'}
                  </button>
                  {currentSessionId && (
                    <button onClick={handleEndSession} disabled={endingSession} className="btn sm">
                      {endingSession ? 'Ending…' : 'Close session only'}
                    </button>
                  )}
                  <button onClick={() => setCurrentView('upload')} className="btn sm primary">+ New Audit</button>
                </div>
              </div>
              {sessions.length === 0 ? (
                <EmptyState
                  title="No sessions yet"
                  hint="Upload a configuration to get started — a session opens automatically and groups the upload."
                  onUpload={() => setCurrentView('upload')}
                />
              ) : (
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead><tr><th>Started</th><th>Status</th><th>Framework</th><th>Nodes</th><th>Pass</th><th>Fail</th><th>Unknown</th><th></th></tr></thead>
                  <tbody>
                    {sessions.map((s) => (
                      <tr key={s.id}>
                        <td className="mono text-xs">{(s.created_at || '').slice(0, 19).replace('T', ' ')}</td>
                        <td><span className={`bdg ${s.status === 'open' ? 'g' : 'n'}`}>{s.status}</span></td>
                        <td>{s.framework}</td>
                        <td>{s.node_count}</td>
                        <td className="text-emerald-500">{s.pass_count}</td>
                        <td className="text-red-500">{s.fail_count}</td>
                        <td className="text-amber-500">{s.unknown_count}</td>
                        <td><button onClick={() => setSelectedSessionId(s.id)} className="btn sm">View nodes</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              )}
            </div>
            )
          )}

          {currentView === 'upload' && (
            <NewAuditFlow
              frameworks={fwList}
              selectedFrameworks={activeFrameworks}
              controls={policy.controls}
              onSetSelection={(frameworks, controls) => updatePolicy({ frameworks, controls })}
              onIngest={(files, framework) => handleFilesUploaded(files, framework)}
              onNavigate={setCurrentView}
              aiSettings={{ mode: aiSettings.mode, air_gapped: aiSettings.air_gapped }}
              aiSaving={aiSaving}
              cloudKeyConfigured={cloudKeyConfigured}
              isAdmin={currentUser?.role === 'Admin'}
              onChooseLane={chooseLane}
              onSetAirGapped={(airGapped) => {
                // Cloud LLM cannot be persisted while air-gapped, so fall back.
                const mode = airGapped && aiSettings.mode === 'cloud_llm' ? 'learned' : aiSettings.mode;
                setAiSettings({ mode, air_gapped: airGapped });
                handleSaveAiSettings({ mode, air_gapped: airGapped });
              }}
              pendingPacks={pendingPacksCount}
              onTrainDecide={runReviewDecisions}
              onTrainDismiss={handleDismissBacklog}
            />
          )}
          {currentView === 'nodes' && (
            nodes.length === 0 ? (
              <EmptyState
                title="No devices yet"
                hint="Upload a configuration to get started. Nothing appears here until you have ingested a device."
                onUpload={() => setCurrentView('upload')}
              />
            ) : (
            <div className="card">
              <div className="card-h">
                <div>
                    <h2>Devices<SectionInfo id="devices" /></h2>
                    <p>{nodes.length} devices · audited configurations and their latest posture. Open a row for adapter tier and raw evidence.</p>
                </div>
                <button onClick={() => setCurrentView('upload')} className="btn sm primary">
                  New Audit
                </button>
              </div>

              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Vendor</th>
                      <th>Platform</th>
                      <th>Hardware Model</th>
                      <th>IP Address</th>
                      <th>Serial Number</th>
                      <th>Controls Evaluated</th>
                      <th>Score</th>
                      <th>Band</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {nodes.map((n) => (
                      <tr key={n.id} className="clickable" onClick={() => openNodeDrawer(n)}>
                        <td><b>{n.name}</b></td>
                        <td>{n.vendor}</td>
                        <td>{n.platform}</td>
                        <td>{n.hardware_model || 'not provided'}</td>
                        <td className="mono text-xs">{n.ip_address || 'not provided'}</td>
                        <td className="mono text-xs">{n.serial || 'not provided'}</td>
                        <td>{`${n.controls_evaluated ?? 0}/${n.controls_total ?? 0}`}</td>
                        <td><b>{n.compliance_score.toFixed(1)}%</b></td>
                        <td><span className={`bdg ${bandTone(n.compliance_band)}`}>{n.compliance_band}</span></td>
                        <td>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              openNodeDrawer(n);
                            }}
                            className="btn sm"
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            )
          )}

          {currentView === 'controls' && (
            nodes.length === 0 ? (
              <EmptyState
                title="No devices yet"
                hint="Upload a configuration to get started — the controls matrix populates from your ingested devices."
                onUpload={() => setCurrentView('upload')}
              />
            ) : (
            <div className="card">
              <div className="card-h">
                <div>
                  <h2>Controls Matrix<SectionInfo id="controls" /></h2>
                  <p>{filteredControls.length} of {scopeControls.length} controls shown · {assessScope === 'uploaded' ? `last uploaded config${lastUploadedName ? ` (${lastUploadedName})` : ''}` : assessScope === 'session' ? 'current session' : `${scopeDevices.length || nodes.length} node(s)`} · policy: {activeFrameworks.map((id) => policyLabel(fwList.find((f) => f.profile_id === id), id)).join(', ')}</p>
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={assessScope}
                    onChange={(e) => setAssessScope(e.target.value as 'session' | 'uploaded' | 'all')}
                    className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]"
                  >
                    <option value="session">Current session</option>
                    <option value="uploaded">Last uploaded config</option>
                    <option value="all">All nodes ({nodes.length})</option>
                  </select>
                  <select
                    value={selectedFramework}
                    onChange={(e) => updatePolicy({ frameworks: [e.target.value] })}
                    className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]"
                  >
                    {fwList.map((f) => (
                      <option key={f.profile_id} value={f.profile_id}>
                        {policyLabel(f)}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => {
                      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scopeControls, null, 2));
                      const a = document.createElement('a');
                      a.href = dataStr;
                      a.download = `inv4r-assessment-${selectedFramework}-${assessScope}.json`;
                      a.click();
                      showToast('Exported assessment JSON', 'success');
                    }}
                    className="btn sm"
                  >
                    Export JSON
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
                <label className="text-xs muted">Result</label>
                <select value={controlResultFilter} onChange={(e) => setControlResultFilter(e.target.value)} className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]">
                  <option value="FAIL_UNKNOWN">Fail &amp; Unknown</option>
                  <option value="FAIL">Fail</option>
                  <option value="UNKNOWN">Unknown</option>
                  <option value="PASS">Pass</option>
                  <option value="NOT_APPLICABLE">Not Applicable</option>
                  <option value="ALL">All</option>
                </select>
                <label className="text-xs muted">Severity</label>
                <select value={controlSeverityFilter} onChange={(e) => setControlSeverityFilter(e.target.value)} className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]">
                  <option value="ALL">All</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
                <input value={controlSearch} onChange={(e) => setControlSearch(e.target.value)} placeholder="Search node name…" className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]" />
                <span className="ml-auto text-xs text-[var(--muted)]">{filteredControls.length} shown</span>
              </div>

              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                      <tr>
                        <th>Control ID</th>
                        <th>Title</th>
                        <th>Node</th>
                        <th>Severity</th>
                        <th>Result</th>
                        <th>Framework</th>
                        <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredControls.length === 0 && (
                      <tr>
                        <td colSpan={7} className="text-center py-4 text-[var(--muted)]">No controls match the current filters.</td>
                      </tr>
                    )}
                    {filteredControls.map((c, idx) => (
                      <tr key={idx}>
                        <td className="mono font-bold text-blue-600 dark:text-blue-400">{c.control_id}</td>
                        <td>{c.title}</td>
                        <td>{c.node}</td>
                        <td>
                          <span className={`bdg ${severityTone(c.severity)}`}>
                            {c.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`bdg ${resultTone(c.result)}`}>
                            {c.result}
                          </span>
                          {(c as any).preview_result && (
                            <span className="bdg n ml-1" title="Provisional preview — pending reviewer approval">
                              Preview: {(c as any).preview_result}
                            </span>
                          )}
                        </td>
                        <td className="text-xs text-[var(--muted)]">
                          {policyLabel(fwList.find((f) => f.profile_id === (c as any).framework), (c as any).framework)}
                        </td>
                        <td>
                          <button onClick={() => openEvidence(c)} className="btn sm">Evidence</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            )
          )}

          {currentView === 'frameworks' && (
            frameworkDetail ? (
              <div className="space-y-4">
                <div className="card">
                  <div className="card-h">
                    <div>
                      <button onClick={() => setFrameworkDetail(null)} className="btn sm">‹ All frameworks</button>
                      <h2 className="mt-3">{policyLabel(frameworkDetail)}</h2>
                      <p>{frameworkDetail.description || frameworkDetail.title}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="bdg b">{frameworkDetail.control_count} controls</span>
                      {currentUser?.role === 'Admin' && (
                        <button onClick={() => setShowAddControl((v) => !v)} className="btn sm">+ Add control</button>
                      )}
                    </div>
                  </div>

                  {showAddControl && currentUser?.role === 'Admin' && (
                    <div className="mx-4 mb-4 border border-[var(--line)] p-4">
                      <p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">ADD CONTROL (advisory validation)</p>
                      <div className="form-grid" style={{ marginTop: 10 }}>
                        <div className="field">
                          <label>Control ID</label>
                          <input value={newControlId} onChange={(e) => setNewControlId(e.target.value)} placeholder="e.g. CIS-1.1.9" />
                        </div>
                        <div className="field">
                          <label>Title</label>
                          <input value={newControlTitle} onChange={(e) => setNewControlTitle(e.target.value)} />
                        </div>
                        <div className="field">
                          <label>Severity</label>
                          <select value={newControlSeverity} onChange={(e) => setNewControlSeverity(e.target.value)}>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                          </select>
                        </div>
                      </div>
                      <div className="form-grid two" style={{ marginTop: 10 }}>
                        <div className="field">
                          <label>Canonical fact (closed vocabulary)</label>
                          <input value={newControlFact} onChange={(e) => setNewControlFact(e.target.value)} placeholder="management.http.enabled" />
                        </div>
                        <div className="field">
                          <label>Expected state</label>
                          <select value={newControlExpect} onChange={(e) => setNewControlExpect(e.target.value)}>
                            <option value="ABSENT">Absent (disabled)</option>
                            <option value="PRESENT">Present (enabled)</option>
                          </select>
                        </div>
                      </div>
                      <button
                        className="btn primary mt-3"
                        onClick={() => addControlToFramework({
                          id: newControlId.trim(), title: newControlTitle.trim(),
                          severity: newControlSeverity, fact: newControlFact.trim() || undefined,
                          expect: { status: newControlExpect },
                        })}
                      >
                        Add to {policyLabel(frameworkDetail)}
                      </button>
                    </div>
                  )}

                  {frameworkDetailLoading ? (
                    <p className="p-4 muted small">Loading controls…</p>
                  ) : (
                    <>
                      <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
                        <label className="flex items-center gap-2 text-xs">
                          <input
                            type="checkbox"
                            checked={activeFrameworks.includes(frameworkDetail.profile_id)}
                            onChange={(e) => toggleFrameworkEvaluated(frameworkDetail.profile_id, e.target.checked)}
                          />
                          Evaluate this framework
                        </label>
                        <button className="btn sm" onClick={() => setFrameworkSelection(frameworkDetail.controls.map((c) => c.control_id))}>Select all</button>
                        <button className="btn sm" onClick={() => setFrameworkSelection([])}>Deselect all</button>
                        <span className="ml-auto text-xs text-[var(--muted)]">{selectionSet.size} of {frameworkDetail.control_count} selected</span>
                      </div>
                      <div className="tbl-wrap">
                        <table className="tbl">
                          <thead><tr><th>Map</th><th>Control</th><th>Title</th><th>Severity</th><th>Category</th></tr></thead>
                          <tbody>
                            {frameworkDetail.controls.map((c) => (
                              <tr key={c.control_id}>
                                <td>
                                  <input type="checkbox" checked={selectionSet.has(c.control_id)}
                                         onChange={() => toggleDetailControl(c.control_id)} />
                                </td>
                                <td className="mono font-bold text-[var(--blue)]">{c.control_id}</td>
                                <td>{c.title}</td>
                                <td><span className={`bdg ${severityTone(c.severity)}`}>{c.severity}</span></td>
                                <td className="text-xs text-[var(--muted)]">{c.category}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </div>
            ) : (
              <div className="row two">
                {fwList.map((fw) => (
                  <div
                    key={fw.profile_id}
                    className="card clickable"
                    onClick={() => openFramework(fw.profile_id)}
                  >
                    <div className="card-h">
                      <div>
                        {/* Exact policy identifier + version — never a descriptive title. */}
                        <h2>{policyLabel(fw)}</h2>
                        <p>{fw.description}</p>
                      </div>
                      <span className={`bdg ${activeFrameworks.includes(fw.profile_id) ? 'g' : 'n'}`}>
                        {activeFrameworks.includes(fw.profile_id) ? 'selected' : 'not selected'}
                      </span>
                    </div>
                    <div className="flex justify-between items-baseline pt-3 border-t border-[var(--line)]">
                      <span className="small muted">Implemented controls</span>
                      <b style={{ fontSize: 20 }}>{fw.control_count}</b>
                    </div>
                  </div>
                ))}
              </div>
            )
          )}

          {currentView === 'reports' && (
            nodes.length === 0 ? (
              <EmptyState
                title="No devices yet"
                hint="Upload a configuration to get started — reports are generated from your ingested devices."
                onUpload={() => setCurrentView('upload')}
              />
            ) : (
            <div className="space-y-4">
              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Fleet Compliance Report (Signed PDF)<SectionInfo id="reports" /></h2>
                    <p>Comprehensive security posture report covering every ingested node and fact provenance</p>
                  </div>
                  <div className="flex gap-2.5">
                    <button
                      onClick={() => handleDownloadPdf(false)}
                      className="btn primary"
                      disabled={!!reviewStatus?.needs_review}
                      title={reviewStatus?.needs_review ? 'Resolve outstanding review items first' : undefined}
                    >
                      Download Fleet PDF
                    </button>
                    {!!reviewStatus?.needs_review && (
                      <button
                        onClick={() => handleDownloadPdf(true)}
                        className="btn"
                        title="Draft fleet report: unresolved lines are listed with the mapping each is suggested to become. Not a final result."
                      >
                        Download preliminary
                      </button>
                    )}
                    <button
                      onClick={() => {
                        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(nodes, null, 2));
                        const a = document.createElement('a');
                        a.href = dataStr;
                        a.download = `inv4r-nodes-${selectedFramework}.json`;
                        a.click();
                        showToast('Exported Fleet Data JSON', 'success');
                      }}
                      className="btn"
                    >
                      Export Fleet JSON
                    </button>
                  </div>
                </div>
              </div>

              {reviewStatus?.needs_review && (
                <div className="card" style={{ borderColor: 'var(--amber)' }}>
                  <div className="card-h" style={{ marginBottom: 0 }}>
                    <div>
                      <h2 style={{ color: 'var(--amber)' }}>
                        Review required: {reviewStatus.outstanding} outstanding item(s) in {reviewScope === 'session' ? 'this session' : 'all sessions'}
                      </h2>
                      <p>
                        Report generation is gated on the backend until every unmapped item in the report's own node scope
                        is reviewed. {(reviewStatus.backlog ?? 0) > 0 && <b>{reviewStatus.backlog} backlog item(s) from earlier sessions do not block this report.</b>}
                        {' '}A preliminary report can be downloaded at any time: it is clearly marked as a draft and lists,
                        for every unresolved line, the mapping it is suggested to become.
                      </p>
                    </div>
                    <button onClick={() => setCurrentView('training')} className="btn primary">
                      Open review queue
                    </button>
                  </div>
                </div>
              )}

              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Individual Node Reports &amp; Dossiers</h2>
                    <p>Export auditable per-device findings, facts, and deterministic invariant verifications</p>
                  </div>
                </div>
                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>Node</th>
                        <th>Vendor</th>
                        <th>Platform</th>
                        <th>Score</th>
                        <th>Band</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {nodes.map((n) => (
                        <tr key={n.id}>
                          <td><b>{n.name}</b></td>
                          <td>{n.vendor}</td>
                          <td>{n.platform}</td>
                          <td><b>{n.compliance_score.toFixed(1)}%</b></td>
                          <td>
                            <span className={`bdg ${bandTone(n.compliance_band)}`}>
                              {n.compliance_band}
                            </span>
                          </td>
                          <td>
                            <div className="flex gap-2">
                              <button
                                onClick={() => handleDownloadNodePdf(n, false)}
                                className="btn sm primary"
                                disabled={!!reviewStatus?.needs_review}
                                title={reviewStatus?.needs_review ? `Resolve ${reviewStatus.outstanding} outstanding review item(s) first` : undefined}
                              >
                                Download PDF
                              </button>
                              {!!reviewStatus?.needs_review && (
                                <button
                                  onClick={() => handleDownloadNodePdf(n, true)}
                                  className="btn sm"
                                  title="Draft dossier: unresolved lines are listed with the mapping each is suggested to become."
                                >
                                  Preliminary
                                </button>
                              )}
                              <button
                                onClick={() => openNodeDrawer(n)}
                                className="btn sm"
                              >
                                View Findings
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            )
          )}

          {currentView === 'verification' && (
            <div className="space-y-4">
              <div className="card">
                <div className="card-h"><div><p className="text-xs font-bold tracking-[0.12em] text-blue-600">BEHAVIORAL VERIFICATION</p><h2>Security invariants</h2><p>Verify that intended security controls are enforced by actual network behavior. A result is shown only after the check actually runs.</p></div><span className="bdg b">Batfish</span></div>

                <div className="space-y-4 max-w-3xl">
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="field">
                      <label>Invariant</label>
                      <select value={selectedInvariantId} onChange={(e) => { setSelectedInvariantId(e.target.value); setVerifyResult(null); }} className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]">
                        {invariants.map((inv) => (
                          <option key={inv.id} value={inv.id}>{inv.id} · {inv.title}</option>
                        ))}
                      </select>
                    </div>
                    <div className="field">
                      <label>Scope</label>
                      <select value={assessScope} onChange={(e) => setAssessScope(e.target.value as 'session' | 'uploaded' | 'all')} className="p-1.5 rounded-lg border border-[var(--line)] bg-[var(--card)] text-xs text-[var(--text)]">
                        <option value="session">Current session</option>
                        <option value="uploaded">Last uploaded config</option>
                        <option value="all">All nodes ({nodes.length})</option>
                      </select>
                    </div>
                    <div className="field">
                      <label>&nbsp;</label>
                      <button onClick={handleRunInvariant} disabled={verifyRunning || !selectedInvariantId} className="btn primary w-full">
                        {verifyRunning ? 'Running…' : 'Run Verification'}
                      </button>
                    </div>
                  </div>

                  {(() => {
                    const inv = invariants.find((i) => i.id === selectedInvariantId);
                    if (!inv) return null;
                    return (
                      <div className="border border-[var(--line)] p-5">
                        <b className="mono">{inv.id}</b>
                        <h3 className="mt-2 text-base font-semibold">{inv.title}</h3>
                        <p className="mt-2 text-sm text-[var(--muted)]">{inv.description}</p>
                        <p className="mt-1 text-sm text-[var(--muted)]">Source: {inv.source} → {inv.destination} · {inv.protocol}/{inv.port} · Expected: <b>{inv.expected}</b></p>
                        <p className="mt-3 text-sm text-[var(--muted)]">Status: {verifyResult ? verifyResult.result : 'Not verified'}</p>
                      </div>
                    );
                  })()}
                </div>

                {verifyRunning && <p className="mt-4 text-sm text-[var(--muted)]">Evaluating forwarding behavior via Batfish…</p>}
                <details className="mt-4"><summary className="cursor-pointer text-sm font-semibold">Advanced verification</summary><p className="mt-2 text-sm text-[var(--muted)]">Use the engineering query interface for custom scenarios and raw Batfish evidence.</p></details>
              </div>
              {!verifyRunning && verifyResult && (
                <div className="card">
                  <div className="card-h">
                    <div>
                      <p className={`text-xs font-bold tracking-[0.12em] ${verifyResult.result === 'FAIL' ? 'text-red-500' : verifyResult.result === 'PASS' ? 'text-emerald-500' : 'text-amber-500'}`}>
                        {verifyResult.result === 'PASS' ? 'INVARIANT HOLDS' : verifyResult.result === 'FAIL' ? 'VERIFIED VIOLATION' : 'INCONCLUSIVE'}
                      </p>
                      <h2>{verifyResult.invariant.id} · {verifyResult.invariant.title}</h2>
                    </div>
                    <span className={`bdg ${resultTone(verifyResult.result)}`}>{verifyResult.result}</span>
                  </div>
                  <div className="grid gap-5 md:grid-cols-3 text-sm">
                    <div><span className="muted">Expected</span><p className="font-semibold">{verifyResult.invariant.expected}</p></div>
                    <div><span className="muted">Observed</span><p className="font-semibold">{verifyResult.behaviour_status}</p></div>
                    <div><span className="muted">Batfish</span><p>{verifyResult.batfish_available ? 'available' : 'not available'}</p></div>
                  </div>
                  <div className="mt-5 border-y border-[var(--line)] py-4">
                    <p className="text-xs font-bold tracking-[0.1em] text-[var(--muted)]">SUMMARY</p>
                    <p className="mt-3 text-sm">{verifyResult.summary}</p>
                    {verifyResult.explanation && <p className="mt-2 text-sm text-[var(--muted)]">{verifyResult.explanation}</p>}
                  </div>
                  {verifyResult.path?.length > 0 && (
                    <div className="mt-4">
                      <p className="text-xs font-bold tracking-[0.1em] text-[var(--muted)]">NETWORK TRACE</p>
                      <p className="mt-2 text-sm">{verifyResult.path.map((h: any) => h.node).join(' → ')}</p>
                    </div>
                  )}
                  <button onClick={() => showToast('Raw Batfish evidence is available in the verification record.', 'info')} className="btn mt-4">View Raw Batfish Result</button>
                </div>
              )}
            </div>
          )}

          {currentView === 'training' && (
            <div className="space-y-4">
              <div className="card">
                <div className="card-h">
                  <div>
                    <h2>Training Queue<SectionInfo id="training-loop" /></h2>
                    <p>Each uploaded configuration has its own queue. A decision maps the same line everywhere it occurs, and the affected evaluation is re-run automatically.</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="bdg a">{reviewQueue?.unresolved ?? 0} unique unresolved</span>
                    {(reviewQueue?.backlog ?? 0) > 0 && (
                      <button
                        className="btn sm"
                        onClick={() => {
                          const next = reviewScope === 'session' ? 'all' : 'session';
                          setReviewScope(next as 'session' | 'all');
                          localStorage.setItem('inv4r.reviewScope', next);
                        }}
                      >
                        {reviewScope === 'session' ? `Show backlog (${reviewQueue?.backlog})` : 'Back to this session'}
                      </button>
                    )}
                  </div>
                </div>

                {!reviewQueue || reviewQueue.items.length === 0 ? (
                  <p className="muted small">
                    {reviewQueue && reviewQueue.backlog > 0
                      ? `Nothing unresolved in ${reviewScope === 'session' ? 'this session' : 'this scope'}, but ${reviewQueue.backlog} unknown line(s) from earlier sessions are in the backlog — use “Show backlog” above to train them.`
                      : 'No unknown fragments in this session — nothing to train. A completed session starts with an empty queue.'}
                  </p>
                ) : (
                  <TrainingQueue
                    items={reviewQueue.items}
                    busy={reviewBusy}
                    selected={selectedReviewKeys}
                    onToggle={toggleReviewKey}
                    onSelectKeys={(keys, on) => setSelectedReviewKeys((prev) => {
                      const set = new Set(prev);
                      keys.forEach((k) => (on ? set.add(k) : set.delete(k)));
                      return Array.from(set);
                    })}
                    onDecide={runReviewDecisions}
                    onDismiss={handleDismissBacklog}
                  />
                )}
              </div>
            </div>
          )}

          {currentView === 'users' && (
            <div className="space-y-4">
              {currentUser.role !== 'Admin' ? (
                <div className="card text-center py-10">
                  <div className="w-12 h-12 mx-auto rounded-full bg-red-900/30 text-red-400 flex items-center justify-center text-xl font-bold mb-3">
                    ♙
                  </div>
                  <h2>Access Restricted</h2>
                  <p className="text-xs text-[var(--muted)] max-w-md mx-auto mb-4">
                    User account provisioning and access approvals are strictly restricted to system Administrators.
                  </p>
                  <button onClick={() => setCurrentView('dashboard')} className="btn primary">
                    Return to Dashboard
                  </button>
                </div>
              ) : (
                <>
                  <div className="card">
                    <div className="card-h">
                      <div>
                        <h2>Create User Account</h2>
                        <p>Directly provision analysts, reviewers, or administrator credentials</p>
                      </div>
                    </div>

                    <form onSubmit={handleAddUserSubmit}>
                      <div className="form-grid">
                        <div className="field">
                          <label>Email Address</label>
                          <input
                            type="email"
                            value={newUserEmail}
                            onChange={(e) => setNewUserEmail(e.target.value)}
                            placeholder="user@organization.corp"
                            required
                          />
                        </div>
                        <div className="field">
                          <label>Full Name</label>
                          <input
                            type="text"
                            value={newUserName}
                            onChange={(e) => setNewUserName(e.target.value)}
                            placeholder="e.g. Rachel Green"
                            required
                          />
                        </div>
                        <div className="field">
                          <label>Role</label>
                          <select
                            value={newUserRole}
                            onChange={(e) => setNewUserRole(e.target.value as any)}
                          >
                            <option value="Analyst">Analyst</option>
                            <option value="Reviewer">Reviewer</option>
                            <option value="Admin">Admin</option>
                          </select>
                        </div>
                      </div>
                      <div className="field">
                        <label>Password / Initial Credential</label>
                        <input
                          type="password"
                          value={newUserPassword}
                          onChange={(e) => setNewUserPassword(e.target.value)}
                          placeholder="Account password (e.g. admin)"
                          required
                        />
                      </div>
                      <button type="submit" className="btn primary">
                        Create User Account
                      </button>
                    </form>
                  </div>

                  <div className="card">
                    <div className="card-h">
                      <div>
                        <h2>
                          Pending Access Requests (
                          {accessRequests.filter((r) => r.status === 'PENDING').length}
                          )
                        </h2>
                        <p>Self-service registration requests submitted from the login portal awaiting review</p>
                      </div>
                    </div>

                    <div className="tbl-wrap">
                      <table className="tbl">
                        <thead>
                          <tr>
                            <th>Requester Name</th>
                            <th>Work Email</th>
                            <th>Requested Role</th>
                            <th>Justification</th>
                            <th>Submitted</th>
                            <th>Status</th>
                            <th>Admin Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {accessRequests.length === 0 ? (
                            <tr>
                              <td colSpan={7} className="text-center py-4 text-[var(--muted)]">
                                No access requests pending review
                              </td>
                            </tr>
                          ) : (
                            accessRequests.map((req) => (
                              <tr key={req.id}>
                                <td><b>{req.name}</b></td>
                                <td>{req.email}</td>
                                <td>
                                  <span className={`bdg ${req.requestedRole === 'Admin' ? 'r' : req.requestedRole === 'Reviewer' ? 'a' : 'n'}`}>
                                    {req.requestedRole}
                                  </span>
                                </td>
                                <td className="text-xs text-[var(--muted)]">{req.justification}</td>
                                <td>{req.submittedAt.slice(0, 16).replace('T', ' ')}</td>
                                <td>
                                  <span
                                    className={`bdg ${
                                      req.status === 'APPROVED' ? 'g' : req.status === 'REJECTED' ? 'r' : 'a'
                                    }`}
                                  >
                                    {req.status}
                                  </span>
                                </td>
                                <td>
                                  {req.status === 'PENDING' ? (
                                    <div className="flex gap-1.5">
                                      <button
                                        onClick={() => handleApproveAccessRequest(req.id, req.requestedRole)}
                                        className="btn sm success"
                                      >
                                        Approve
                                      </button>
                                      <button
                                        onClick={() => handleRejectAccessRequest(req.id)}
                                        className="btn sm danger"
                                      >
                                        Reject
                                      </button>
                                    </div>
                                  ) : (
                                    <span className="text-xs text-[var(--muted)]">Decided</span>
                                  )}
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div className="card">
                    <div className="card-h">
                      <div>
                        <h2>Active User Accounts ({users.length})</h2>
                        <p>All active accounts provisioned with RBAC authorization</p>
                      </div>
                    </div>

                    <div className="tbl-wrap">
                      <table className="tbl">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Provisioned</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {users.map((u) => (
                            <tr key={u.email}>
                              <td><b>{u.name}</b></td>
                              <td>{u.email}</td>
                              <td>
                                <span className={`bdg ${u.role === 'Admin' ? 'r' : u.role === 'Reviewer' ? 'a' : 'n'}`}>
                                  {u.role}
                                </span>
                              </td>
                              <td>{u.createdAt.slice(0, 10)}</td>
                              <td>
                                {u.email !== 'admin@inv4r.io' && u.email !== 'admin' ? (
                                  <button onClick={() => handleDeleteUser(u.email)} className="btn sm danger">
                                    Delete
                                  </button>
                                ) : (
                                  <span className="text-xs text-[var(--muted)] font-mono">Primary Root</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}


        </main>
      </div>

      {newSessionPrompt && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: 'fixed', inset: 0, zIndex: 60, display: 'flex',
            alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.55)',
          }}
        >
          <div className="card" style={{ maxWidth: 520, margin: 16 }}>
            <div className="card-h">
              <div>
                <h2>Start a new session?</h2>
                <p>
                  {newSessionPrompt.pending} item(s) are unresolved. Move them to the backlog and start a new session?
                </p>
              </div>
            </div>
            <p className="small muted">
              Unresolved items are kept in the backlog and remain resolvable. Learned mappings, approved decisions and
              mapping packs are never deleted by starting a new session.
            </p>
            <div className="flex gap-2" style={{ marginTop: 12 }}>
              <button onClick={performNewSession} disabled={startingSession} className="btn primary">
                {startingSession ? 'Starting…' : 'Confirm'}
              </button>
              <button onClick={() => setNewSessionPrompt(null)} disabled={startingSession} className="btn">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div
        className={`drawer-backdrop ${activeDrawer ? 'open' : ''}`}
        onClick={() => setActiveDrawer(null)}
      ></div>

      <div className={`drawer ${activeDrawer ? 'open' : ''}`}>
        <div className="drawer-h">
          <h2>
            {activeDrawer?.type === 'node' && `Node: ${activeDrawer.data.filename}`}
            {activeDrawer?.type === 'training' && `Training Queue · ${activeDrawer.data.name}`}
            {activeDrawer?.type === 'verification' && `Classify Invariant · ${activeDrawer.data.control_id}`}
          </h2>
          <button onClick={() => setActiveDrawer(null)} className="text-xl font-bold p-1">
            ✕
          </button>
        </div>

        <div className="drawer-body">
          {activeDrawer?.type === 'node' && (
            <div className="space-y-4">
              <dl className="kv">
                <dt>Vendor</dt><dd>{activeDrawer.data.vendor}</dd>
                <dt>Platform</dt><dd>{activeDrawer.data.platform}</dd>
                <dt>Adapter</dt><dd className="mono">{activeDrawer.data.adapter} · Tier {activeDrawer.data.tier}</dd>
                <dt>Coverage</dt><dd>L{activeDrawer.data.coverage_level} · {activeDrawer.data.coverage_name}</dd>
                <dt>Compliance Score</dt><dd><b>{activeDrawer.data.compliance_score.toFixed(1)}%</b></dd>
                <dt>Evidence ID</dt><dd className="mono">{activeDrawer.data.evidence_id}</dd>
                <dt>SHA-256</dt><dd className="mono text-[11px] truncate">{activeDrawer.data.hashes.sha256}</dd>
              </dl>

              <h3 className="font-bold text-sm pt-3 border-t border-[var(--line)]">
                Extracted Facts ({activeDrawer.data.facts.length})
              </h3>
              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr><th>Fact</th><th>Value</th><th>Confidence</th></tr>
                  </thead>
                  <tbody>
                    {activeDrawer.data.facts.map((f: any, idx: number) => (
                      <tr key={idx}>
                        <td className="mono text-xs">{f.name}</td>
                        <td className="mono text-xs">{String(f.value)}</td>
                        <td>{f.confidence.toFixed(2)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h3 className="font-bold text-sm pt-3 border-t border-[var(--line)]">Raw Configuration</h3>
              <pre className="code">{activeDrawer.data.raw_config}</pre>
            </div>
          )}

          {activeDrawer?.type === 'training' && (
            <div className="space-y-4">
              <p className="small muted">
                Vendor: {activeDrawer.data.vendor} · Platform: {activeDrawer.data.platform}
              </p>

              <h3 className="font-bold text-sm">Pending Discovered Lines ({activeDrawer.data.unknown_fragments.length})</h3>
              {activeDrawer.data.unknown_fragments.map((frag: any) => (
                <div key={frag.proposal_id} className="card p-3 border border-[var(--line)]">
                  <div
                    className="code mb-2"
                    title="Unresolved line — no canonical fact yet (unknown evidence)"
                    style={{
                      background: 'color-mix(in srgb, var(--amber) 22%, transparent)',
                      borderLeft: '3px solid var(--amber)',
                    }}
                  >
                    {frag.raw_text}
                  </div>
                  <div className="text-xs text-[var(--muted)] mb-2">
                    Category: <b>{frag.category}</b> · Suggested: <b>{frag.suggested_fact || 'none'}</b>
                  </div>
                  <div className="flex gap-2">
                    <input
                      id={`train-input-${frag.proposal_id}`}
                      defaultValue={frag.suggested_fact || ''}
                      placeholder="Fact parameter name"
                      className="p-1.5 border border-[var(--line)] rounded text-xs flex-1 bg-[var(--card)]"
                    />
                    <button
                      onClick={() => {
                        const input = document.getElementById(`train-input-${frag.proposal_id}`) as HTMLInputElement;
                        handleDecideFragment(activeDrawer.data.id, frag.proposal_id, 'APPROVED', input.value);
                      }}
                      className="btn sm success"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => {
                        handleDecideFragment(activeDrawer.data.id, frag.proposal_id, 'REJECTED');
                      }}
                      className="btn sm danger"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeDrawer?.type === 'verification' && (
            <div className="space-y-4">
              <dl className="kv">
                <dt>Control ID</dt><dd className="mono">{activeDrawer.data.control_id}</dd>
                <dt>Audit Result</dt><dd><span className="bdg r">{activeDrawer.data.audit_result}</span></dd>
                <dt>Expected</dt><dd>{activeDrawer.data.expected_behavior}</dd>
                <dt>Batfish Path</dt><dd><span className="bdg g">PASS</span></dd>
                <dt>Correlation</dt><dd><span className="bdg a">CONTRADICTORY</span></dd>
              </dl>

              <div className="p-3 rounded bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200">
                Notice: Security invariant rule strictly forbids automatically treating contradictions as false positives. Human review and signed justification are required.
              </div>

              <div className="field">
                <label>Review Classification</label>
                <select id="verClassificationSelect">
                  <option value="CONFIRMED_FALSE_POSITIVE">Confirmed false positive</option>
                  <option value="AUDIT_RULE_VALID">Audit rule valid</option>
                  <option value="BATFISH_MODEL_LIMITATION">Batfish model limitation</option>
                  <option value="INSUFFICIENT_CONTEXT">Insufficient context</option>
                  <option value="OTHER">Other</option>
                </select>
              </div>

              <div className="field">
                <label>Technical Rationale</label>
                <textarea
                  id="verReasonTextarea"
                  placeholder="Explain why this invariant is verified or why behavior diverges from configuration…"
                  defaultValue="Forwarding proof confirms inbound Telnet port 23 is dropped at boundary interface ACL before reaching CPU."
                ></textarea>
              </div>

              <button
                onClick={() => {
                  const sel = (document.getElementById('verClassificationSelect') as HTMLSelectElement).value;
                  const reason = (document.getElementById('verReasonTextarea') as HTMLTextAreaElement).value;
                  handleClassifyVerification(activeDrawer.data.verification_id, sel, reason);
                }}
                className="btn primary"
              >
                Submit Classification
              </button>
            </div>
          )}
        </div>
      </div>

      {evidenceControl && (
        <EvidencePanel
          control={evidenceControl}
          rawConfig={evidenceRaw}
          filename={evidenceControl.node}
          preview={evidencePreview}
          loading={evidenceLoading}
          onClose={() => {
            setEvidenceControl(null);
            setEvidenceRaw('');
            setEvidenceLoading(false);
          }}
        />
      )}

      {toastMessage && (
        <div className={`toast ${toastMessage.type === 'success' ? 'success' : toastMessage.type === 'error' ? 'error' : ''}`}>
          {toastMessage.text}
        </div>
      )}
    </div>
  );
}
