// Single dashboard-wide status/severity color mapping.
// Bands mirror the compliance engine's scoring config
// (inv4r/controls/engine.py): severities critical|high|medium|low and risk
// bands strong|moderate|weak|critical. Do not invent new bands — extend the
// engine config and update this map together.

export type BadgeTone = 'g' | 'a' | 'r' | 'b' | 'n';

const SEVERITY: Record<string, BadgeTone> = {
  critical: 'r',
  high: 'r',
  medium: 'a',
  low: 'b',
};

const RESULT: Record<string, BadgeTone> = {
  PASS: 'g',
  FAIL: 'r',
  UNKNOWN: 'a',
  NOT_APPLICABLE: 'n',
};

const BAND: Record<string, BadgeTone> = {
  strong: 'g',
  moderate: 'a',
  weak: 'r',
  critical: 'r',
  high: 'g',
  medium: 'a',
  unknown: 'n',
  n_a: 'n',
};

export function severityTone(severity: string | undefined): BadgeTone {
  return SEVERITY[String(severity || '').toLowerCase()] || 'n';
}

export function resultTone(result: string | undefined): BadgeTone {
  return RESULT[String(result || '').toUpperCase()] || 'n';
}

export function bandTone(band: string | undefined): BadgeTone {
  return BAND[String(band || '').toLowerCase()] || 'n';
}
