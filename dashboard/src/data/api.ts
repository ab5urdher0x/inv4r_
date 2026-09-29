

const TOKEN_KEY = 'inv4r.token';

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setToken(token: string) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T = any>(method: string, path: string, body?: unknown, opts?: { raw?: 'blob' }): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  let resp: Response;
  try {
    resp = await fetch(path, { method, headers, body: payload, credentials: 'same-origin' });
  } catch {
    throw new ApiError(0, 'Cannot reach the INV4R server. Is the backend running?');
  }

  if (resp.status === 401 && !path.includes('/auth/login')) {
    setToken('');
  }
  if (!resp.ok) {
    let msg = resp.statusText || `HTTP ${resp.status}`;
    try {
      const j = await resp.json();
      msg = j.detail || j.error || (typeof j === 'string' ? j : msg);
      if (Array.isArray(msg)) msg = msg.map((m: any) => m.msg || String(m)).join('; ');
    } catch {  }
    throw new ApiError(resp.status, String(msg));
  }
  if (opts?.raw === 'blob') return resp.blob() as unknown as T;
  const ct = resp.headers.get('content-type') || '';
  return (ct.includes('json') ? resp.json() : resp.text()) as Promise<T>;
}

export const api = {
  get: <T = any>(p: string) => req<T>('GET', p),
  post: <T = any>(p: string, body?: unknown) => req<T>('POST', p, body),
  postForm: <T = any>(p: string, form: FormData) => req<T>('POST', p, form),
  blob: (p: string) => req<Blob>('GET', p, undefined, { raw: 'blob' }),
};

export interface BackendUser {
  email: string;
  name: string;
  role: 'Admin' | 'Reviewer' | 'Analyst';
}

export interface BackendNode {
  id: string;
  name: string;
  path: string;
  vendor: string;
  platform: string;
  adapter: string;
  tier: number;
  facts_count: number;
  unknown_count: number;
  coverage_level: number;
  coverage_name: string;
  compliance_score: number;
  compliance_band: string;
  controls_evaluated?: number;
  controls_total?: number;
  ip_address?: string;
  serial?: string;
  hardware_model?: string;
  session_id?: string;
  file_size: number;
  evidence_id: string;
  sha256: string;
  duplicate: boolean;
}

export interface BackendSession {
  id: string;
  created_at: string;
  closed_at?: string | null;
  framework: string;
  status: string;
  node_count: number;
  pass_count: number;
  fail_count: number;
  unknown_count: number;
}

export interface BackendReviewItem {
  key: string;
  raw_text: string;
  raw_path: string;
  category: string;
  category_label: string;
  vendor: string;
  platform: string;
  suggested_fact?: string | null;
  suggestion_confidence: number;
  suggested_by: string;
  nodes: string[];
  affected_count: number;
  /** Already decided in this scope (kept visible but not actionable). */
  resolved: boolean;
  /** APPROVED / REJECTED / DISMISSED — why the row is resolved. */
  resolution: string;
  /** The canonical fact an APPROVED row was mapped to ('' for a rejection). */
  applied_fact: string;
}

export interface BackendInvariant {
  id: string;
  title: string;
  description: string;
  source: string;
  destination: string;
  protocol: string;
  port: number | null;
  expected: string;
}

export interface BackendInvariantResult {
  invariant: BackendInvariant;
  result: 'PASS' | 'FAIL' | 'UNKNOWN';
  behaviour_status: string;
  summary: string;
  explanation: string;
  path: Array<{ node: string; interface?: string; detail?: string }>;
  batfish_available: boolean;
  evidence: Array<{ kind: string; summary: string; detail: any }>;
  server_time: string;
}

export interface BackendNodeDetail {
  id: string;
  name: string;
  vendor: string;
  platform: string;
  os_version: string;
  model_hint: string;
  adapter: string;
  tier: number;
  coverage_level: number;
  coverage_name: string;
  coverage_reasons: string[];
  raw_config: string;
  raw_lines_count: number;
  hashes: Record<string, string>;
  evidence_id: string;
  facts: Array<{ name: string; value: any; status: string; confidence: number; source_adapter: string; evidence_lines: number[] }>;
  compliance: { framework?: string; score?: number; band?: string; controls?: any[] };
  controls_summary: Record<string, number>;
  unknown_fragments: any[];
  detection_confidence: number;
  candidate_vendors: string[];
}

export interface BackendFramework {
  profile_id: string;
  title: string;
  /** Exact policy identifier from profile metadata (e.g. "CIS"). */
  framework?: string;
  version: string;
  description: string;
  control_count: number;
}

export type FrameworkSummary = BackendFramework;

export interface BackendFrameworkControl {
  control_id: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  rationale: string;
}

export interface BackendFrameworkDetail {
  profile_id: string;
  title: string;
  framework: string;
  version: string;
  description: string;
  control_count: number;
  controls: BackendFrameworkControl[];
}

/** Definition submitted by an Admin to add a control via the user overlay. */
export interface ControlDefinitionInput {
  id: string;
  title: string;
  severity: string;
  fact?: string;
  expect?: Record<string, unknown>;
  any_of?: Array<Record<string, unknown>>;
  all_of?: Array<Record<string, unknown>>;
  applicable_when?: Record<string, unknown>;
  rationale?: string;
  description?: string;
  remediation?: Record<string, string[]>;
}

export interface BackendMappingPack {
  map_id: string;
  vendor: string;
  platform: string;
  version: string;
  status: string;
  created_by: string;
  created_at: string;
  approved_by: string;
  approved_at: string;
  rules_count: number;
  active_rules: number;
}

export interface BackendProposal {
  proposal_id: string;
  raw_path: string;
  raw_text: string;
  category: string;
  suggested_fact?: string | null;
  suggestion_confidence?: number;
  suggested_by?: string;
  status?: string;
}

export function titleCaseVendor(v: string): string {
  if (!v) return 'Unknown';
  // A genuinely unrecognized vendor is labelled honestly. The old slug
  // title-casing produced "Unknown Vendorx" from "unknown-vendorx", a
  // concatenation bug rather than a real vendor name.
  if (v.toLowerCase() === 'unknown') return 'Unrecognized';
  if (v.toLowerCase().startsWith('unknown-')) {
    const rest = v.slice('unknown-'.length).replace(/[-_]/g, ' ').trim().toLowerCase();
    return rest ? `Unrecognized (${rest})` : 'Unrecognized';
  }
  const map: Record<string, string> = {
    'cisco-ios': 'Cisco', 'cisco-iosxe': 'Cisco', 'cisco': 'Cisco',
    'juniper-junos': 'Juniper', 'juniper': 'Juniper',
    'fortinet-fortigate': 'Fortinet', 'fortinet': 'Fortinet',
    'arista-eos': 'Arista', 'arista': 'Arista',
    'paloalto-panos': 'Palo Alto', 'paloalto': 'Palo Alto',
    'sonic': 'SONiC', 'openconfig': 'OpenConfig',
    'aws-security-group': 'AWS',
  };
  if (map[v]) return map[v];
  return v.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const sha256Of = async (text: string): Promise<string> => {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    let h = 0;
    for (let i = 0; i < text.length; i++) h = ((h << 5) - h + text.charCodeAt(i)) | 0;
    return Math.abs(h).toString(16).padStart(64, '0');
  }
};

export function nodeFromBackend(n: BackendNode): any {
  return {
    id: n.id,
    name: n.name,
    filename: n.name,
    vendor: titleCaseVendor(n.vendor),
    platform: n.platform,
    adapter: n.adapter,
    tier: n.tier,
    facts_count: n.facts_count,
    unknown_count: n.unknown_count,
    coverage_level: n.coverage_level,
    coverage_name: n.coverage_name || 'Full Deterministic',
    compliance_score: n.compliance_score ?? 0,
    compliance_band: (n.compliance_band || 'unknown').toUpperCase(),
    controls_evaluated: n.controls_evaluated ?? 0,
    controls_total: n.controls_total ?? 0,
    ip_address: n.ip_address || '',
    serial: n.serial || '',
    hardware_model: n.hardware_model || '',
    session_id: n.session_id || '',
    duplicate: n.duplicate,
    evidence_id: n.evidence_id,
    hashes: { sha256: n.sha256 || '', md5: (n.sha256 || '').slice(0, 12) },
    raw_lines_count: 0,
    raw_config: '',
    os_version: '',
    device_metadata: { hostname: '', model_hint: n.hardware_model || '' },
    facts: [],
    control_results: [],
    unknown_fragments: [],
    decided_fragments: [],
    __detailLoaded: false,
  };
}

export function applyNodeDetail(node: any, d: BackendNodeDetail): any {
  return {
    ...node,
    id: d.id,
    vendor: titleCaseVendor(d.vendor),
    platform: d.platform,
    adapter: d.adapter,
    tier: d.tier,
    facts_count: d.facts?.length ?? node.facts_count,
    unknown_count: d.unknown_fragments?.filter((f) => (f.status || 'PENDING') === 'PENDING').length ?? node.unknown_count,
    coverage_level: d.coverage_level,
    coverage_name: d.coverage_name || node.coverage_name,
    raw_lines_count: d.raw_lines_count,
    raw_config: d.raw_config,
    os_version: d.os_version || '',
    device_metadata: { hostname: d.os_version ? node.device_metadata?.hostname || '' : '', model_hint: d.model_hint || '' },
    hashes: Object.keys(d.hashes || {}).length ? d.hashes : node.hashes,
    evidence_id: d.evidence_id || node.evidence_id,
    facts: (d.facts || []).map((f) => ({
      name: f.name,
      value: f.value,
      confidence: f.confidence,
      source_adapter: f.source_adapter,
    })),
    control_results: (d.compliance?.controls || []).map((c: any) => ({
      control_id: c.control_id,
      title: c.title,
      severity: String(c.severity || 'MEDIUM').toUpperCase(),
      result: String(c.result || 'UNKNOWN').toUpperCase(),
      detail: c.detail || '',
      node: d.name,
      framework: c.framework || '',
      evidence_lines: c.evidence_lines || [],
      remediation: c.remediation || '',
      remediation_cli_sequence: c.remediation_cli_sequence || [],
      // Deterministic policy data only — never a generated command.
      has_remediation: !!c.has_remediation,
      expected: c.expected || '',
      observed: c.observed || '',
      reason: c.reason || '',
    })),
    unknown_fragments: (d.unknown_fragments || [])
      .filter((f: any) => (f.status || 'PENDING') === 'PENDING')
      .map((f: any) => ({
        proposal_id: f.proposal_id,
        raw_path: f.raw_path,
        raw_text: f.raw_text,
        category: f.category,
        suggested_fact: f.suggested_fact ?? undefined,
        suggestion_confidence: f.suggestion_confidence,
        suggested_by: f.suggested_by,
      })),
    decided_fragments: (d.unknown_fragments || [])
      .filter((f: any) => (f.status || 'PENDING') !== 'PENDING')
      .map((f: any) => ({
        proposal_id: f.proposal_id,
        raw_text: f.raw_text,
        status: f.status,
        decided_fact: f.decided_fact ?? undefined,
        approver: f.approver || '',
      })),
    detection_confidence: d.detection_confidence,
    candidate_vendors: d.candidate_vendors || [],
    __detailLoaded: true,
  };
}

export function controlsFromAssess(devices: any[]): any[] {
  return devices.flatMap((dev) =>
    (dev.control_results || []).map((c: any) => ({
      control_id: c.control_id,
      title: c.title,
      severity: String(c.severity || 'MEDIUM').toUpperCase(),
      result: String(c.result || 'UNKNOWN').toUpperCase(),
      detail: c.detail || '',
      node: dev.filename || dev.device_id,
      framework: c.framework || '',
      evidence_lines: c.evidence_lines || [],
      remediation: c.remediation || '',
      remediation_cli_sequence: c.remediation_cli_sequence || [],
      has_remediation: !!c.has_remediation,
      expected: c.expected || '',
      observed: c.observed || '',
      reason: c.reason || '',
    }))
  );
}

export interface AssessQuery {
  frameworks: string[];
  controls?: string;
  nodeId?: string;
  sessionId?: string;
  preview?: boolean;
}

/** Assessment scoped to the shared policy selection (never all frameworks). */
export async function fetchAssess(q: AssessQuery): Promise<any> {
  const params = new URLSearchParams({ frameworks: q.frameworks.join(',') });
  if (q.controls) params.set('controls', q.controls);
  if (q.nodeId) params.set('node_id', q.nodeId);
  if (q.sessionId) params.set('session_id', q.sessionId);
  if (q.preview) params.set('preview', 'true');
  return api.get(`/api/assess?${params.toString()}`);
}

export function fetchNodeDetail(nodeId: string, opts: {
  frameworks: string[]; controls?: string; preview?: boolean;
}): Promise<BackendNodeDetail> {
  const params = new URLSearchParams({ frameworks: opts.frameworks.join(',') });
  if (opts.controls) params.set('controls', opts.controls);
  if (opts.preview) params.set('preview', 'true');
  return api.get(`/api/nodes/${encodeURIComponent(nodeId)}?${params.toString()}`);
}

export function fetchFrameworkDetail(profileId: string): Promise<BackendFrameworkDetail> {
  return api.get(`/api/frameworks/${encodeURIComponent(profileId)}`);
}

export function addFrameworkControl(
  profileId: string, control: ControlDefinitionInput,
): Promise<BackendFrameworkDetail> {
  return api.post(`/api/frameworks/${encodeURIComponent(profileId)}/controls`, control);
}

export function fetchSessions(): Promise<{ sessions: BackendSession[]; total: number; current_session_id: string }> {
  return api.get('/api/sessions');
}

export function endSession(): Promise<{
  status: string; session: BackendSession | null; nodes_cleared: number;
}> {
  return api.post('/api/sessions/end', {});
}

/** Close the open session, clear its devices, and open a fresh one.
 *  Learned knowledge is kept; the closing session's devices are not. */
export function startNewSession(framework?: string): Promise<{
  status: string; session: BackendSession | null; previous: BackendSession | null;
  backlog: number; nodes_cleared: number;
}> {
  const q = framework ? `?framework=${encodeURIComponent(framework)}` : '';
  return api.post(`/api/sessions/new${q}`, {});
}

export function fetchNodes(sessionId?: string): Promise<{ nodes: BackendNode[]; total: number }> {
  const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
  return api.get(`/api/nodes${q}`);
}

export function fetchReviewQueue(sessionId?: string | null, nodeId?: string | null): Promise<{
  items: BackendReviewItem[]; total: number; unresolved: number;
  categories: Record<string, number>; resolved: number;
  backlog: number; scope: string; session_id: string;
}> {
  const params = new URLSearchParams();
  // A node scope is narrower than a session scope: the audit workflow asks for
  // exactly the configuration it just ingested.
  if (nodeId) params.set('node_id', nodeId);
  else if (sessionId) params.set('session_id', sessionId);
  const q = params.toString() ? `?${params.toString()}` : '';
  return api.get(`/api/review/queue${q}`);
}

export function fetchReviewStatus(sessionId?: string | null): Promise<{
  framework: string; needs_review: boolean; outstanding: number;
  nodes: any[]; session_id: string; backlog: number;
}> {
  const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
  return api.get(`/api/assessment/review-status${q}`);
}

/** Clear stale backlog items deliberately (no mapping decision recorded). */
export function dismissReview(keys: string[]): Promise<{
  status: string; dismissed: number; unresolved: number; backlog: number;
}> {
  return api.post('/api/review/dismiss', { keys });
}

export function decideReview(decisions: Array<{ key: string; decision: string; fact?: string }>) {
  return api.post('/api/review/decide', { decisions });
}

export function approveReviewCategory(category: string, fact?: string) {
  return api.post('/api/review/approve-category', { category, fact });
}

export function fetchInvariants(): Promise<{ invariants: BackendInvariant[] }> {
  return api.get('/api/behaviour/invariants');
}

export interface InvariantOverride {
  source?: string;
  destination?: string;
  port?: number;
  node_id?: string;
  qtype?: string;
}

export function verifyInvariant(
  invariant_id: string,
  session_id?: string | null,
  overrides?: InvariantOverride,
): Promise<BackendInvariantResult> {
  return api.post('/api/behaviour/verify', {
    invariant_id,
    session_id: session_id || null,
    ...(overrides || {}),
  });
}

export function summarizeAssessDevice(dev: any): {
  device_id: string; filename: string; vendor: string; platform: string;
  score: number; band: string; facts_count: number; unknown_count: number;
  pass: number; fail: number; unknown: number;
} {
  const cs = dev.controls_summary || {};
  return {
    device_id: dev.device_id,
    filename: dev.filename || dev.device_id,
    vendor: dev.vendor,
    platform: dev.platform,
    score: typeof dev.compliance_score === 'number' ? dev.compliance_score : 0,
    band: String(dev.compliance_band || 'unknown').toUpperCase(),
    facts_count: dev.facts_count ?? 0,
    unknown_count: dev.unknown_count ?? 0,
    pass: cs.pass ?? 0, fail: cs.fail ?? 0, unknown: cs.unknown ?? 0,
  };
}

export function packFromBackend(p: BackendMappingPack): any {
  return {
    map_id: p.map_id,
    vendor: titleCaseVendor(p.vendor),
    platform: p.platform,
    version: p.version || '1.0',
    status: (p.status || 'PENDING_REVIEW').toUpperCase(),
    active_rules: p.active_rules ?? 0,
    rules_count: p.rules_count ?? 0,
    created_by: p.created_by || '',
    created_at: p.created_at || '',
    approved_by: p.approved_by || '',
    approved_at: p.approved_at || '',
  };
}

export async function fingerprintFile(file: File): Promise<string> {
  const text = await file.text().catch(() => file.name);
  return sha256Of(`${file.name}:${file.size}:${text}`);
}

export { sha256Of };
