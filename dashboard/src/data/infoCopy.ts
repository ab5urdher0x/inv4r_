// Central copy for the per-section "i" info buttons. Keep every explainer
// here instead of inlining strings across components.

export const INFO_COPY: Record<string, string> = {
  'compliance-overview':
    'How each compliance framework is progressing across the fleet. Pass rate and control counts come from the latest assessment against the selected framework.',
  'control-monitoring':
    'Failed control tests across the current scope: one bar per selected framework (Pass / Fail / Unknown side by side), then the failing categories underneath for triage.',
  'node-compliance':
    'Per-device posture. The summary shows fleet pass/fail/unknown counts and the highest-risk devices; open the full table to inspect every node.',
  'training-loop':
    'Human-in-the-loop review of configuration lines the adapters could not map. Approving a fragment teaches the learned matcher; AI only proposes here, it never decides.',
  'reports':
    'Signed compliance PDFs and JSON exports. Report generation is blocked until every unmapped item from the latest assessment has been reviewed.',
  'mapping-packs':
    'Runtime mapping rules persisted from approved training decisions. Active packs deterministically replay learned mappings across restarts and deployments.',
  'normalization-schema':
    'The closed security-fact vocabulary every adapter normalizes into. Nothing outside this list can enter the fact store.',
  'controls':
    'Every control evaluated in the current scope, with its severity and deterministic PASS/FAIL/UNKNOWN result. UNKNOWN means the evidence was insufficient.',
  'frameworks':
    'The compliance frameworks available for assessment, with their hardened control counts.',
  'devices':
    'Every ingested configuration with its detected vendor, adapter tier, extracted facts, and compliance posture.',
};

export function infoFor(id: string): string | undefined {
  return INFO_COPY[id];
}
