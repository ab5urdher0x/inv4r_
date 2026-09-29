// Single source of truth for the selected policy and controls.
//
// Every view (upload evaluation, Recent File, Control Results, Evidence,
// Training Queue, re-evaluation, Dashboard, Compliance Overview) reads this
// selection, and the backend is asked to evaluate ONLY the selected
// framework(s) and controls. An unselected framework is never evaluated — not
// for results, statistics, the training queue, evidence or remediation.

import type { FrameworkSummary } from './api';

export type AssessmentScope = 'session' | 'uploaded' | 'all';

export interface PolicySelection {
  /** Selected framework profile ids. Never empty (falls back to the default). */
  frameworks: string[];
  /** Selected control ids per framework; 'ALL' means every control in it. */
  controls: Record<string, string[] | 'ALL'>;
  /** Which nodes the assessment is scoped to. */
  scope: AssessmentScope;
}

export const DEFAULT_FRAMEWORK = 'cis-network-baseline';

const STORAGE_KEY = 'inv4r.policySelection';
const LEGACY_FRAMEWORK_KEY = 'inv4r.framework';
const LEGACY_UPLOAD_KEY = 'inv4r.uploadFramework';
const LEGACY_SCOPE_KEY = 'inv4r.assessScope';

function readScope(): AssessmentScope {
  const saved = localStorage.getItem(LEGACY_SCOPE_KEY);
  return saved === 'uploaded' || saved === 'all' ? saved : 'session';
}

export function loadPolicySelection(): PolicySelection {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<PolicySelection>;
      const frameworks = Array.isArray(parsed.frameworks)
        ? parsed.frameworks.filter((f): f is string => typeof f === 'string' && !!f)
        : [];
      return {
        frameworks: frameworks.length ? frameworks : [DEFAULT_FRAMEWORK],
        controls: (parsed.controls as PolicySelection['controls']) || {},
        scope: parsed.scope === 'uploaded' || parsed.scope === 'all' ? parsed.scope : 'session',
      };
    }
  } catch {
    /* fall through to legacy/defaults */
  }
  // Migrate the two legacy single-framework keys into one selection.
  const legacy = localStorage.getItem(LEGACY_FRAMEWORK_KEY)
    || localStorage.getItem(LEGACY_UPLOAD_KEY)
    || DEFAULT_FRAMEWORK;
  return { frameworks: [legacy], controls: {}, scope: readScope() };
}

export function savePolicySelection(selection: PolicySelection): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(selection));
  } catch {
    /* storage is best-effort */
  }
}

/** Frameworks that will actually be evaluated (never an empty list). */
export function selectedFrameworks(selection: PolicySelection): string[] {
  return selection.frameworks.length ? selection.frameworks : [DEFAULT_FRAMEWORK];
}

export function controlsFor(selection: PolicySelection, profileId: string): string[] | 'ALL' {
  return selection.controls[profileId] || 'ALL';
}

/**
 * Control filter for the API, or undefined when every selected framework uses
 * its full control set.
 *
 * Ids are qualified with their framework id (`<profile>:<control>`). The server
 * narrows a framework only by the entries that name it, so leaving one
 * framework on ALL never gets it filtered by another framework's subset — the
 * selection is per framework, not a union applied to all of them.
 */
export function controlsParam(selection: PolicySelection): string | undefined {
  const parts = selectedFrameworks(selection).flatMap((profileId) => {
    const picked = selection.controls[profileId];
    if (!picked || picked === 'ALL' || !picked.length) return [];
    return picked.map((controlId) => `${profileId}:${controlId}`);
  });
  return parts.length ? parts.join(',') : undefined;
}

/** True when at least one framework has an explicit (non-ALL) control subset. */
export function hasControlSubset(selection: PolicySelection): boolean {
  return selectedFrameworks(selection).some((f) => {
    const picked = selection.controls[f];
    return !!picked && picked !== 'ALL' && picked.length > 0;
  });
}

/**
 * Display label for a policy: the exact framework identifier plus its version
 * from policy metadata (e.g. "CIS v1.1"). Falls back to the profile id — never
 * a descriptive title such as "Network Device Hardening Baseline".
 */
export function policyLabel(fw: Pick<FrameworkSummary, 'framework' | 'profile_id' | 'version'> | undefined,
                            profileId?: string): string {
  if (!fw) return profileId || '';
  const identifier = fw.framework?.trim() || fw.profile_id;
  return fw.version ? `${identifier} v${fw.version}` : identifier;
}
