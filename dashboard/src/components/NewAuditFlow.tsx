import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Check, ChevronLeft, ChevronRight, LoaderCircle, Plus, Upload } from 'lucide-react';
import { api, ApiError, fetchFrameworkDetail, fetchNodeDetail, fetchReviewQueue } from '../data/api';
import type { BackendFrameworkDetail, BackendReviewItem, FrameworkSummary } from '../data/api';
import { controlsParam as buildControlsParam, policyLabel } from '../data/policy';
import { severityTone, resultTone } from '../data/severity';
import { EvidencePanel, type EvidenceControl } from './EvidencePanel';
import { TrainingQueue } from './TrainingQueue';

type Controls = Record<string, string[] | 'ALL'>;

/** One control row as returned by /api/nodes/{id} and /api/assess. */
const buildControls = (list: any[]) => list.map((c: any) => ({
  control_id: c.control_id,
  title: c.title,
  severity: String(c.severity || 'MEDIUM').toUpperCase(),
  result: String(c.result || 'UNKNOWN').toUpperCase(),
  detail: c.detail || '',
  framework: c.framework || '',
  evidence_lines: c.evidence_lines || [],
  remediation: c.remediation || '',
  remediation_cli_sequence: c.remediation_cli_sequence || [],
  has_remediation: !!c.has_remediation,
  expected: c.expected || '',
  observed: c.observed || '',
  reason: c.reason || '',
}));

type Props = {
  frameworks: FrameworkSummary[];
  selectedFrameworks: string[];
  controls: Controls;
  /** Replace the whole selection (frameworks + per-framework control subset). */
  onSetSelection: (frameworks: string[], controls: Controls) => void;
  onIngest: (files: File[], framework: string) => Promise<any[]>;
  onNavigate: (view: string) => void;
  // AI recognition lane — visible while uploading (admins can change it here).
  aiSettings: { mode: string; air_gapped: boolean };
  aiSaving: boolean;
  cloudKeyConfigured: boolean;
  isAdmin: boolean;
  onChooseLane: (mode: string) => void;
  onSetAirGapped?: (airGapped: boolean) => void;
  /** PENDING_REVIEW packs present → the flow also shows a provisional preview. */
  pendingPacks: number;
  onOpenSettings?: () => void;
  /** Records training decisions and re-runs the affected evaluation. */
  onTrainDecide: (decisions: Array<{ key: string; decision: string; fact?: string }>) => Promise<number>;
  onTrainDismiss: (keys: string[]) => Promise<void> | void;
};

const LANE_LABEL: Record<string, string> = {
  learned: 'Own model (learned matcher, offline)',
  local_llm: 'Local LLM (loopback)',
  cloud_llm: 'Cloud LLM (connected)',
  rules: 'Deterministic rules only',
};

export function NewAuditFlow({
  frameworks, selectedFrameworks, controls, onSetSelection, onIngest, onNavigate,
  aiSettings, aiSaving, cloudKeyConfigured, isAdmin, onChooseLane, onSetAirGapped,
  pendingPacks, onOpenSettings, onTrainDecide, onTrainDismiss,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [step, setStep] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [cli, setCli] = useState('');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [complete, setComplete] = useState(false);

  const [details, setDetails] = useState<Record<string, BackendFrameworkDetail>>({});
  const [expanded, setExpanded] = useState<string | null>(null);

  const [result, setResult] = useState<any>(null);
  const [resultError, setResultError] = useState<string | null>(null);
  const [evidenceControl, setEvidenceControl] = useState<EvidenceControl | null>(null);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  // Unknown lines discovered in THIS configuration (node-scoped queue).
  const [queue, setQueue] = useState<BackendReviewItem[] | null>(null);
  const [trainBusy, setTrainBusy] = useState(false);
  const [trainSelected, setTrainSelected] = useState<string[]>([]);
  const [reEvaluated, setReEvaluated] = useState(false);

  const activeFrameworks = selectedFrameworks.length ? selectedFrameworks : [frameworks[0]?.profile_id].filter(Boolean);
  // Same framework-qualified filter the rest of the dashboard sends, so the
  // audit evaluates exactly the selection shown in the checklist.
  const controlsParam = useMemo(
    () => buildControlsParam({ frameworks: activeFrameworks, controls, scope: 'session' }),
    [activeFrameworks, controls],
  );
  const controlsFor = (id: string): string[] | 'ALL' => controls[id] || 'ALL';

  const resultControls: any[] = result?.controls || [];
  const resultFails = resultControls.filter((c) => c.result === 'FAIL');
  const resultUnknowns = resultControls.filter((c) => c.result === 'UNKNOWN');
  const resultPasses = resultControls.filter((c) => c.result === 'PASS').length;
  const sevCount = (s: string) => resultFails.filter((c) => c.severity === s).length;
  const resultLabel = (id: string) => policyLabel(frameworks.find((f) => f.profile_id === id), id);

  // --- Unknowns are resolved here, before any report is generated ----------
  const unresolvedItems = (queue || []).filter((i) => !i.resolved);
  const unresolvedCount = unresolvedItems.length;
  // Every gate step needs the node-scoped queue to have loaded at least once,
  // so a slow fetch never marks "reviewed" prematurely.
  const unknownsReviewed = complete && queue !== null && unresolvedCount === 0;

  const readQueue = async (filename: string) => {
    try {
      const q = await fetchReviewQueue(null, filename);
      setQueue(q.items || []);
      return q.items || [];
    } catch {
      /* the queue is best-effort: the backend gate still protects the report */
      return [];
    }
  };

  /** Re-read this node's authoritative results (plus the preview when packs
   *  are pending) so the flow always shows the freshest evaluation. */
  const reloadResult = async (filename: string) => {
    const opts = { frameworks: activeFrameworks, controls: controlsParam };
    const d = await fetchNodeDetail(filename, opts);
    let list = buildControls(d.compliance?.controls || []);
    if (pendingPacks > 0) {
      try {
        const p = await fetchNodeDetail(filename, { ...opts, preview: true });
        const byId = new Map(buildControls(p.compliance?.controls || []).map((c: any) => [c.control_id, c]));
        list = list.map((c: any) => {
          const pc: any = byId.get(c.control_id);
          return pc && pc.result !== c.result ? { ...c, preview_result: pc.result } : c;
        });
      } catch { /* preview is best-effort */ }
    }
    setResult((prev: any) => ({
      ...(prev || {}),
      filename,
      vendor: d.vendor,
      platform: d.platform,
      os_version: d.os_version,
      facts_count: d.facts?.length ?? 0,
      coverage_level: d.coverage_level,
      score: d.compliance?.score ?? 0,
      band: String(d.compliance?.band || 'unknown').toUpperCase(),
      raw_config: d.raw_config || '',
      controls: list,
    }));
  };

  /** A decision is applied globally, then this audit is re-evaluated: the
   *  authoritative results update without the operator re-running the audit. */
  const applyDecisions = async (
    decisions: Array<{ key: string; decision: string; fact?: string }>,
  ) => {
    const filename = result?.filename;
    if (!decisions.length || !filename) return;
    setTrainBusy(true);
    try {
      await onTrainDecide(decisions);
      await readQueue(filename);
      await reloadResult(filename);
      setReEvaluated(true);
    } finally {
      setTrainBusy(false);
      setTrainSelected([]);
    }
  };

  const dismissItems = async (keys: string[]) => {
    const filename = result?.filename;
    if (!keys.length || !filename) return;
    setTrainBusy(true);
    try {
      await onTrainDismiss(keys);
      await readQueue(filename);
      await reloadResult(filename);
      setReEvaluated(true);
    } finally {
      setTrainBusy(false);
      setTrainSelected([]);
    }
  };

  // Load a framework's real control list when the operator opens it.
  useEffect(() => {
    if (step !== 2) return;
    activeFrameworks.forEach((id) => {
      if (details[id]) return;
      fetchFrameworkDetail(id)
        .then((d) => setDetails((prev) => ({ ...prev, [id]: d })))
        .catch(() => { /* control list is best-effort */ });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, activeFrameworks.join(',')]);

  const toggleFramework = (id: string) => {
    const next = activeFrameworks.includes(id)
      ? activeFrameworks.filter((x) => x !== id)
      : [...activeFrameworks, id];
    onSetSelection(next.length ? next : [id], controls);
  };

  const setControlSubset = (id: string, ids: string[] | 'ALL') => {
    onSetSelection(activeFrameworks, { ...controls, [id]: ids });
  };

  const chooseFile = (next: File | undefined) => {
    if (!next) return;
    setFile(next);
    setCli('');
    setComplete(false);
  };

  const goRun = async () => {
    const upload = file || (cli.trim() ? new File([cli], 'pasted-configuration.cfg', { type: 'text/plain' }) : null);
    if (!upload || !activeFrameworks.length) return;
    setRunning(true);
    setProgress(0);
    setResult(null);
    setResultError(null);
    setQueue(null);
    setTrainSelected([]);
    setReEvaluated(false);
    const stages = [20, 38, 55, 70, 84, 94];
    for (const amount of stages) {
      await new Promise((resolve) => window.setTimeout(resolve, 380));
      setProgress(amount);
    }
    try {
      const ingested = await onIngest([upload], activeFrameworks[0]);
      setProgress(96);
      const filename = ingested[0]?.id;
      if (!filename) throw new Error('Engine returned no result for this configuration.');

      // Authoritative results plus the unknowns still to resolve. No report is
      // produced from an unresolved audit.
      setResult({ filename });
      await reloadResult(filename);
      await readQueue(filename);
      setProgress(100);
      setComplete(true);
    } catch (err: any) {
      setResultError(err?.message || 'Audit failed');
      setProgress(100);
      setComplete(true);
    } finally {
      setRunning(false);
    }
  };

  // A preliminary report may always be downloaded: it is clearly marked as a
  // draft and prints the mapping each unresolved line is *suggested* to become.
  // The final report still requires this configuration's queue to be clear, and
  // the backend gate enforces exactly the same rule.
  const handleDownloadPdfReport = async (preliminary = false) => {
    if (!result?.filename) return;
    const draft = preliminary || unresolvedCount > 0;
    if (!draft && unresolvedCount > 0) {
      setPdfError(`${unresolvedCount} unknown line(s) in this configuration are still unresolved. `
        + 'Resolve them in the training queue below, then download the final report.');
      return;
    }
    const fw = activeFrameworks[0] || 'cis-network-baseline';
    setPdfBusy(true);
    setPdfError(null);
    try {
      const blob = await api.blob(`/api/report/pdf?node_id=${encodeURIComponent(result.filename)}&framework=${encodeURIComponent(fw)}${draft ? '&preliminary=true' : ''}`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `inv4r-report-${result.filename.replace(/\.[^.]+$/, '')}${draft ? '-preliminary' : ''}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 409) {
        setPdfError(`${err.message} Open the Training Queue to resolve them, then download again.`);
      } else if (err instanceof ApiError && err.status === 404) {
        setPdfError('This device is no longer ingested. Re-run the audit and try again.');
      } else {
        setPdfError('Could not generate the PDF report: ' + (err?.message || String(err)));
      }
    } finally {
      setPdfBusy(false);
    }
  };

  // The last two steps are gated on this configuration's unknowns being
  // resolved — the report is never presented as ready before that.
  const flowSteps = [
    'Configuration uploaded', 'Evidence fingerprint created', 'Vendor identified',
    'Configuration normalized', 'Security facts extracted',
    ...activeFrameworks.map(resultLabel), 'Finding correlation',
    'Unknown lines reviewed', 'Report generated',
  ];

  const stages = ['Configuration', 'Frameworks', 'Review', 'Audit'];
  const name = file?.name.replace(/\.[^.]+$/, '') || (cli ? 'Pasted configuration' : 'SITL2-B');

  return <div className="space-y-5 text-[var(--text)]">
    <div className="flex flex-col gap-3 border-b border-[var(--line)] pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div><p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">NEW AUDIT</p><h2 className="mt-1 text-2xl font-semibold text-[var(--text)]">{stages[step - 1]}</h2></div>
      <button onClick={() => onNavigate('upload')} className="btn primary flex items-center gap-2"><Plus size={15}/> New Audit</button>
    </div>
    <ol className="grid grid-cols-4 border border-[var(--line)] bg-[var(--card)]">
      {stages.map((label, i) => <li key={label} className={`flex items-center gap-2 px-3 py-3 text-xs font-semibold ${i + 1 === step ? 'bg-[var(--blue)] text-white' : i + 1 < step ? 'text-[var(--green)]' : 'text-[var(--muted)]'}`}><span>{i + 1 < step ? <Check size={14}/> : `0${i + 1}`}</span><span className="hidden sm:inline">{label}</span></li>)}
    </ol>

    {step === 1 && <div className="grid gap-5 lg:grid-cols-[1.4fr_.8fr]">
      <section className="card"><div className="card-h"><div><h2>Upload network configurations</h2><p>Configuration files are fingerprinted before analysis.</p></div></div>
        <input ref={inputRef} className="hidden" type="file" accept=".cfg,.conf,.txt,.json,.xml,.yaml,.yml,.zip" onChange={(e) => chooseFile(e.target.files?.[0])}/>
        <button onClick={() => inputRef.current?.click()} className="flex min-h-56 w-full flex-col items-center justify-center border-2 border-dashed border-[var(--line)] bg-[var(--hover)] text-center hover:border-[var(--blue)]">
          <Upload className="mb-3 text-[var(--blue)]" size={30}/><strong>Drop configuration files here</strong><span className="my-1 text-sm text-[var(--muted)]">or Browse Files</span><span className="text-xs tracking-wide text-[var(--muted)]">CFG · CONF · TXT · JSON · XML · YAML · ZIP</span>
        </button>
        {file && <div className="mt-3 flex items-center gap-2 text-sm text-[var(--green)]"><Check size={16}/><b>{file.name}</b> ready for analysis</div>}
        <div className="my-4 flex items-center gap-3 text-xs text-[var(--muted)]"><span className="h-px flex-1 bg-[var(--line)]"/>OR<span className="h-px flex-1 bg-[var(--line)]"/></div>
        <details className="border border-[var(--line)] p-3"><summary className="cursor-pointer text-sm font-semibold">Paste CLI Configuration</summary><textarea value={cli} onChange={(e) => { setCli(e.target.value); setFile(null); }} placeholder="Paste device configuration" className="mt-3 min-h-32 w-full border border-[var(--line)] bg-[var(--bg)] p-3 text-xs text-[var(--text)]"/></details>
      </section>
      <aside className="space-y-5">
        {/* AI recognition lane is visible during ingestion, not buried in settings. */}
        <div className="card">
          <p className="text-xs font-bold tracking-[0.12em] text-[var(--muted)]">AI RECOGNITION LANE</p>
          <h2 className="mt-3">{LANE_LABEL[aiSettings.mode] || aiSettings.mode}</h2>
          <p className="muted small mt-1">{aiSettings.air_gapped ? 'Air-gapped · no traffic leaves the host' : 'Connected · cloud models permitted'}</p>
          <p className="muted small mt-2">
            AI only proposes mappings for syntax the deterministic adapters cannot
            resolve — it never changes a compliance verdict.
          </p>
          {isAdmin && (
            <div className="flex flex-wrap gap-2 mt-3">
              <button type="button" disabled={aiSaving} onClick={() => onChooseLane('learned')} className="btn sm">Offline matcher</button>
              <button type="button" disabled={aiSaving} onClick={() => onChooseLane('local_llm')} className="btn sm">Local LLM</button>
              <button
                type="button"
                disabled={aiSaving || aiSettings.air_gapped || !cloudKeyConfigured}
                onClick={() => onChooseLane('cloud_llm')}
                className="btn sm"
                title={cloudKeyConfigured ? undefined : 'Add a cloud API key first (Admin)'}
              >
                Cloud LLM
              </button>
            </div>
          )}
        </div>
      </aside>
      <div className="lg:col-span-2 flex justify-end"><button disabled={(!file && !cli.trim())} onClick={() => setStep(2)} className="btn primary disabled:opacity-40">Continue <ChevronRight size={15}/></button></div>
    </div>}

    {step === 2 && <section className="card">
      <div className="card-h"><div><p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">POLICY SELECTION</p><h2>Select framework(s) and, optionally, controls</h2><p>Only the selected policy and controls are evaluated — nothing else is scored.</p></div></div>
      <div className="grid gap-3 md:grid-cols-2">
        {frameworks.map((fw) => {
          const checked = activeFrameworks.includes(fw.profile_id);
          const detail = details[fw.profile_id];
          const picked = controlsFor(fw.profile_id);
          const pickedCount = picked === 'ALL' ? (detail?.control_count ?? fw.control_count) : picked.length;
          return (
            <div key={fw.profile_id} className={`border p-4 ${checked ? 'border-[var(--blue)] bg-[var(--blueSoft)]' : 'border-[var(--line)] bg-[var(--card)]'}`}>
              <button type="button" onClick={() => toggleFramework(fw.profile_id)} className="flex w-full gap-3 text-left">
                <span className={`mt-0.5 flex h-5 w-5 items-center justify-center border ${checked ? 'border-[var(--blue)] bg-[var(--blue)] text-white' : 'border-[var(--line)]'}`}>{checked && <Check size={14}/>}</span>
                <span>
                  <b className="block text-[var(--text)]">{policyLabel(fw)}</b>
                  <span className="mt-1 block text-xs text-[var(--muted)]">{fw.control_count} controls</span>
                </span>
              </button>
              {checked && (
                <>
                  <button type="button" className="btn sm mt-3" onClick={() => setExpanded(expanded === fw.profile_id ? null : fw.profile_id)}>
                    {expanded === fw.profile_id ? 'Hide controls' : `Choose controls (${pickedCount} selected)`}
                  </button>
                  {expanded === fw.profile_id && detail && (
                    <div className="mt-3 border-t border-[var(--line)] pt-3">
                      <div className="flex gap-2">
                        <button type="button" className="btn sm" onClick={() => setControlSubset(fw.profile_id, 'ALL')}>Select all</button>
                        <button type="button" className="btn sm" onClick={() => setControlSubset(fw.profile_id, [])}>Deselect all</button>
                      </div>
                      <div className="mt-2 max-h-52 overflow-auto text-xs">
                        {detail.controls.map((c) => {
                          const on = picked === 'ALL' || picked.includes(c.control_id);
                          return (
                            <label key={c.control_id} className="flex items-center gap-2 border-b border-[var(--line)] py-1">
                              <input
                                type="checkbox"
                                checked={on}
                                onChange={() => {
                                  const base = picked === 'ALL' ? detail.controls.map((x) => x.control_id) : [...picked];
                                  const next = on ? base.filter((x) => x !== c.control_id) : [...base, c.control_id];
                                  setControlSubset(fw.profile_id, next);
                                }}
                              />
                              <span className="mono">{c.control_id}</span>
                              <span className="text-[var(--muted)]">{c.title}</span>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          );
        })}
      </div>
      <div className="mt-5 flex items-center justify-between border-t border-[var(--line)] pt-4">
        <div><b>{activeFrameworks.length} framework(s)</b><span className="ml-4 text-sm text-[var(--muted)]">{activeFrameworks.map(resultLabel).join(', ')}</span></div>
        <div className="flex gap-2"><button onClick={() => setStep(1)} className="btn"><ChevronLeft size={15}/> Back</button><button disabled={!activeFrameworks.length} onClick={() => setStep(3)} className="btn primary">Continue <ChevronRight size={15}/></button></div>
      </div>
    </section>}

    {step === 3 && <section className="card max-w-3xl"><div className="card-h"><div><p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">REVIEW AUDIT</p><h2>Ready to assess</h2></div></div><div className="grid gap-5 md:grid-cols-3 text-sm"><div><b>Configuration</b><hr className="my-3 border-[var(--line)]"/><p className="font-semibold">{name}</p><p className="text-[var(--muted)]">Vendor, facts and coverage are determined by the engine during the audit.</p></div><div><b>Policy</b><hr className="my-3 border-[var(--line)]"/>{activeFrameworks.map((id) => <p key={id} className="text-[var(--green)]">✓ {resultLabel(id)}</p>)}<p className="text-[var(--muted)]">{controlsParam ? `Controls: ${controlsParam.split(',').length} selected` : 'All controls selected'}</p></div><div><b>Verification</b><hr className="my-3 border-[var(--line)]"/><p className="text-[var(--green)]">✓ Deterministic assessment</p><p className="text-[var(--green)]">✓ Evidence capture</p><p className="text-[var(--green)]">✓ Behavioral verification available</p></div></div><div className="mt-6 flex justify-between border-t border-[var(--line)] pt-4"><button onClick={() => setStep(2)} className="btn"><ChevronLeft size={15}/> Back</button><button onClick={() => { setStep(4); goRun(); }} className="btn primary">Run Audit</button></div></section>}    {step === 4 && <section className="space-y-5"><div className="card max-w-3xl"><p className="text-xs font-bold tracking-[0.12em] text-[var(--blue)]">{complete ? (unknownsReviewed ? 'AUDIT COMPLETE' : 'AUDIT COMPLETE · UNKNOWNS PENDING') : 'RUNNING AUDIT'}</p><h2 className="mt-2">{name}</h2>{running && <div className="mt-5 h-1.5 bg-[var(--line)]"><div className="h-full bg-[var(--blue)] transition-all" style={{width: `${progress}%`}}/></div>}<div className="mt-5 space-y-2 text-sm">{flowSteps.map((label, i) => {
        const gateStep = label === 'Unknown lines reviewed' || label === 'Report generated';
        const done = gateStep ? unknownsReviewed : (progress >= Math.min(100, (i + 1) * 12) || complete);
        return <div key={label} className={done ? 'text-[var(--green)]' : gateStep ? 'text-[var(--amber)]' : 'text-[var(--muted)]'}>{done ? '✓' : gateStep ? '○' : running && i === 5 ? '⟳' : '○'} {label}{gateStep && !done && queue !== null && unresolvedCount > 0 ? ` — ${unresolvedCount} left` : ''}</div>;
      })}</div>{resultError && <p className="mt-4 text-sm text-red-500">{resultError}</p>}</div>
      {complete && result && <>
        <div className="card">
          <div className="card-h">
            <div>
              <h2>Security Posture</h2>
              <p>{result.filename} · {result.vendor} {result.platform}{result.os_version ? ` · ${result.os_version}` : ''}</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex flex-col items-end gap-1">
                <button
                  onClick={() => handleDownloadPdfReport(false)}
                  className="btn primary"
                  disabled={pdfBusy || unresolvedCount > 0}
                  title={unresolvedCount > 0 ? `Resolve ${unresolvedCount} unknown line(s) to unlock the final report` : undefined}
                >
                  {pdfBusy ? 'Generating PDF…' : unresolvedCount > 0 ? `Final report locked · ${unresolvedCount} unknown` : 'Download PDF Report'}
                </button>
                {unresolvedCount > 0 && (
                  <button
                    onClick={() => handleDownloadPdfReport(true)}
                    className="btn sm"
                    disabled={pdfBusy}
                    title="Draft report: every unresolved line is listed with the mapping it is suggested to become. Not a final result."
                  >
                    Download preliminary report ({unresolvedCount} unknown)
                  </button>
                )}
              </div>
              <div className="text-right">
                <strong className="text-3xl">{Number(result.score).toFixed(1)} / 100</strong>
                <div className="mt-1 text-xs text-[var(--muted)]">{activeFrameworks.map(resultLabel).join(' · ')}</div>
              </div>
            </div>
          </div>
          {unresolvedCount > 0 && (
            <p className="mt-4 border border-[var(--line)] bg-[var(--hover)] p-3 text-xs text-[var(--amber)]">
              This configuration has {unresolvedCount} unknown line(s) the deterministic adapters could not map. Deal with them in the
              training queue below — the audit re-evaluates automatically and the final report unlocks once the queue is clear. A
              preliminary report is downloadable now: it marks itself as a draft and lists what each unknown line is suggested to become.
            </p>
          )}
          {reEvaluated && unresolvedCount === 0 && (
            <p className="mt-4 border border-[var(--line)] bg-[var(--hover)] p-3 text-xs text-[var(--green)]">
              Final results — every unknown line was resolved and this configuration was re-evaluated. The report is now available.
            </p>
          )}
          {pdfError && <p className="mt-4 border border-[var(--line)] bg-[var(--hover)] p-3 text-xs text-red-500">{pdfError}</p>}
          <div className="grid grid-cols-6 gap-2 border-t border-[var(--line)] pt-4 text-center">
            <div><b className="text-red-500">{sevCount('CRITICAL')}</b><p className="text-xs text-[var(--muted)]">Critical</p></div>
            <div><b className="text-orange-500">{sevCount('HIGH')}</b><p className="text-xs text-[var(--muted)]">High</p></div>
            <div><b className="text-amber-500">{sevCount('MEDIUM')}</b><p className="text-xs text-[var(--muted)]">Medium</p></div>
            <div><b className="text-blue-500">{sevCount('LOW')}</b><p className="text-xs text-[var(--muted)]">Low</p></div>
            <div><b className="text-[var(--green)]">{resultPasses}</b><p className="text-xs text-[var(--muted)]">Passed</p></div>
            <div><b>{resultUnknowns.length}</b><p className="text-xs text-[var(--muted)]">Unknown</p></div>
          </div>
        </div>

        {/* The unknowns of THIS configuration, resolvable in place. A decision
            re-runs the evaluation above and unlocks the report. */}
        <div className="card">
          <div className="card-h">
            <div>
              <h2>Training Queue — {result.filename}</h2>
              <p>
                Unresolved lines still needing a decision in this configuration.
                Every decision is applied to the same line everywhere it occurs,
                and this audit is re-evaluated automatically.
              </p>
            </div>
            <span className={`bdg ${unresolvedCount ? 'a' : 'g'}`}>
              {queue === null ? 'loading…' : unresolvedCount ? `${unresolvedCount} unresolved` : 'all resolved'}
            </span>
          </div>
          {queue === null ? (
            <p className="muted small">Reading this configuration's unknown lines…</p>
          ) : unresolvedCount === 0 ? (
            <p className="muted small">All unknown lines have been resolved — nothing left to decide.</p>
          ) : (
            <TrainingQueue
              items={unresolvedItems}
              busy={trainBusy}
              selected={trainSelected}
              onToggle={(key) => setTrainSelected((prev) => (
                prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
              ))}
              onSelectKeys={(keys, on) => setTrainSelected((prev) => {
                const set = new Set(prev);
                keys.forEach((k) => (on ? set.add(k) : set.delete(k)));
                return Array.from(set);
              })}
              onDecide={applyDecisions}
              onDismiss={dismissItems}
            />
          )}
        </div>

        <div className="card">
          <div className="card-h">
            <div>
              <h2>Control Results</h2>
              <p>{resultControls.length} controls evaluated against {result.filename}</p>
            </div>
          </div>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead><tr><th>Control</th><th>Title</th><th>Severity</th><th>Result</th><th></th></tr></thead>
              <tbody>
                {resultControls.map((c) => (
                  <tr key={`${c.framework}-${c.control_id}`}>
                    <td className="mono font-bold text-[var(--blue)]">{c.control_id}</td>
                    <td>{c.title}</td>
                    <td><span className={`bdg ${severityTone(c.severity)}`}>{c.severity}</span></td>
                    <td>
                      <span className={`bdg ${resultTone(c.result)}`}>{c.result}</span>
                      {c.preview_result && (
                        <span className="bdg n ml-1" title="Provisional preview — pending reviewer approval">
                          Preview: {c.preview_result}
                        </span>
                      )}
                    </td>
                    <td><button className="btn sm" onClick={() => setEvidenceControl(c)}>Evidence</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </>}
      {complete && !result && !resultError && <div className="card"><p className="text-sm muted">No result available for this configuration.</p></div>}
    </section>}

    {evidenceControl && (
      <EvidencePanel
        control={evidenceControl}
        rawConfig={result?.raw_config || ''}
        filename={result?.filename}
        preview={!!evidenceControl.preview_result}
        onClose={() => setEvidenceControl(null)}
      />
    )}
  </div>;
}
