import React, { useMemo } from 'react';
import { severityTone } from '../data/severity';

/**
 * The single detailed view for a control result.
 *
 * Left  — the raw configuration with the exact evidence lines highlighted.
 * Right — a human-readable remediation narrative plus, only when validated
 *         policy data provides it, the vendor-specific suggested configuration.
 *
 * It never invents commands: `remediation_cli_sequence` is populated from the
 * control's policy mapping and is empty for UNKNOWN results.
 */

export interface EvidenceControl {
  control_id: string;
  title: string;
  severity: string;
  result: string;
  detail?: string;
  node?: string;
  framework?: string;
  evidence_lines?: number[];
  remediation?: string;
  remediation_cli_sequence?: string[];
  has_remediation?: boolean;
  expected?: string;
  observed?: string;
  reason?: string;
  /** True when this row comes from a provisional (PENDING_REVIEW) pack. */
  preview_result?: boolean;
}

type Tone = 'fail' | 'unknown' | 'pass' | 'na';

const TONE_VAR: Record<Tone, string> = {
  fail: 'var(--red)',
  unknown: 'var(--amber)',
  pass: 'var(--green)',
  na: 'var(--muted)',
};

const TONE_LABEL: Record<Tone, string> = {
  fail: 'Failed evidence',
  unknown: 'Unknown evidence',
  pass: 'Passed evidence',
  na: 'Reference lines',
};

function toneFor(result: string | undefined): Tone {
  const r = String(result || '').toUpperCase();
  if (r === 'FAIL') return 'fail';
  if (r === 'UNKNOWN') return 'unknown';
  if (r === 'PASS') return 'pass';
  return 'na';
}

export function EvidencePanel({
  control, rawConfig, filename, preview = false, loading = false, onClose,
}: {
  control: EvidenceControl | null;
  rawConfig: string;
  filename?: string;
  preview?: boolean;
  loading?: boolean;
  onClose: () => void;
}) {
  const lines = useMemo(() => (rawConfig || '').split('\n'), [rawConfig]);
  const highlights = useMemo(
    () => new Set((control?.evidence_lines || []).filter((n) => Number.isFinite(n))),
    [control],
  );
  const tone = toneFor(control?.result);
  const cli = control?.remediation_cli_sequence || [];
  const showCli = !!control?.has_remediation && cli.length > 0;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/40"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <aside
        className="flex h-full w-full max-w-5xl flex-col overflow-hidden bg-[var(--card)] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-start justify-between gap-4 border-b border-[var(--line)] p-5">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="bdg b">{control?.framework || filename || 'control'}</span>
              <span className={`bdg ${severityTone(control?.severity)}`}>{control?.severity}</span>
              <span className={`bdg ${control?.result === 'PASS' ? 'g' : control?.result === 'FAIL' ? 'r' : 'a'}`}>
                {control?.result}
              </span>
              {preview && <span className="bdg n">Provisional · pending approval</span>}
            </div>
            <h2 className="mt-2">{control?.title || 'Evidence & Remediation'}</h2>
            <p className="mono text-xs text-[var(--muted)]">
              {control?.control_id}{control?.node ? ` · ${control.node}` : ''}
            </p>
          </div>
          <button onClick={onClose} className="btn sm">Close</button>
        </header>

        {loading ? (
          <div className="p-6 text-sm text-[var(--muted)]">Loading configuration evidence…</div>
        ) : (
          <div className="grid min-h-0 flex-1 gap-0 md:grid-cols-2">
            <section className="flex min-h-0 flex-col border-b border-[var(--line)] md:border-b-0 md:border-r">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-3">
                <div>
                  <p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">RAW CONFIGURATION</p>
                  <p className="text-xs text-[var(--muted)]">{filename || control?.node}</p>
                </div>
                <span className="text-xs font-semibold" style={{ color: TONE_VAR[tone] }}>
                  {TONE_LABEL[tone]}
                </span>
              </div>
              <div className="min-h-0 flex-1 overflow-auto">
                {lines.length === 0 || (lines.length === 1 && !lines[0]) ? (
                  <p className="p-5 text-sm text-[var(--muted)]">No raw configuration available for this evidence.</p>
                ) : (
                  <pre className="m-0 text-xs leading-6">
                    {lines.map((text, idx) => {
                      const n = idx + 1;
                      const marked = highlights.has(n);
                      return (
                        <div
                          key={n}
                          className="flex items-start gap-3 px-4"
                          title={marked ? `${TONE_LABEL[tone]} — matched line for ${control?.control_id}` : undefined}
                          style={marked ? {
                            background: `color-mix(in srgb, ${TONE_VAR[tone]} 22%, transparent)`,
                            borderLeft: `3px solid ${TONE_VAR[tone]}`,
                          } : undefined}
                        >
                          <span
                            className="w-10 shrink-0 select-none text-right"
                            style={marked ? { color: TONE_VAR[tone], fontWeight: 700 } : { color: 'var(--muted)' }}
                          >
                            {n}
                          </span>
                          <code className="mono whitespace-pre-wrap break-all">{text || ' '}</code>
                        </div>
                      );
                    })}
                  </pre>
                )}
              </div>
            </section>

            <section className="min-h-0 overflow-auto p-5">
              <p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">REMEDIATION</p>

              <div className="mt-4 space-y-4 text-sm">
                <div>
                  <p className="text-xs font-bold text-[var(--muted)]">WHAT IS WRONG</p>
                  <p className="mt-1">{control?.observed || control?.detail || 'No observation was recorded.'}</p>
                </div>
                <div>
                  <p className="text-xs font-bold text-[var(--muted)]">WHY IT MATTERS</p>
                  <p className="mt-1">{control?.reason || 'Not documented for this control.'}</p>
                </div>
                <div>
                  <p className="text-xs font-bold text-[var(--muted)]">WHAT SHOULD CHANGE</p>
                  <p className="mt-1">{control?.expected || 'See the control description.'}</p>
                </div>

                {control?.result === 'UNKNOWN' && (
                  <div className="border border-amber-400 p-3 text-xs text-amber-600">
                    This result is unresolved, so no definitive fix is shown. Map the matching
                    configuration in the Training Queue and re-evaluate.
                  </div>
                )}

                <div>
                  <p className="text-xs font-bold text-[var(--muted)]">SUGGESTED CONFIGURATION</p>
                  {showCli ? (
                    <pre className="mt-2 overflow-auto border border-[var(--line)] bg-[var(--bg)] p-3 text-xs">
                      {cli.join('\n')}
                    </pre>
                  ) : (
                    <p className="mt-1 text-[var(--muted)]">
                      No deterministic vendor-specific configuration exists for this control
                      {' '}and the detected platform.
                    </p>
                  )}
                </div>
              </div>
            </section>
          </div>
        )}
      </aside>
    </div>
  );
}
