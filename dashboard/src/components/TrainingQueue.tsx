import React, { useMemo } from 'react';
import type { BackendReviewItem } from '../data/api';

/**
 * Training queue grouped by uploaded configuration.
 *
 * Each uploaded file gets its own section so unknown examples from different
 * configurations are never merged into one indistinguishable queue. Items whose
 * raw line occurs in more than one file are shown once in a "shared" section.
 *
 * Resolved rows are never rendered: a decision is work that is done, so the
 * queue only ever lists lines that still need a human decision.
 */

export interface TrainingQueueProps {
  items: BackendReviewItem[];
  busy: boolean;
  selected: string[];
  onToggle: (key: string) => void;
  onSelectKeys: (keys: string[], selected: boolean) => void;
  onDecide: (decisions: Array<{ key: string; decision: string; fact?: string }>) => void;
  onDismiss: (keys: string[]) => void;
}

const factInputId = (key: string) => `tq-fact-${key}`;

function readFact(key: string, fallback: string | undefined): string {
  const el = document.getElementById(factInputId(key)) as HTMLInputElement | null;
  return (el?.value ?? fallback ?? '').trim();
}

export function TrainingQueue({
  items, busy, selected, onToggle, onSelectKeys, onDecide, onDismiss,
}: TrainingQueueProps) {
  // The moment a line is resolved it leaves the queue — the backend ledger
  // keeps the history, the UI shows only what still needs a decision.
  const openItems = useMemo(() => items.filter((i) => !i.resolved), [items]);

  const sections = useMemo(() => {
    const byNode: Record<string, BackendReviewItem[]> = {};
    const shared: BackendReviewItem[] = [];
    for (const it of openItems) {
      const nodes = it.nodes || [];
      if (nodes.length > 1) {
        shared.push(it);
        continue;
      }
      const name = nodes[0] || 'unassigned configuration';
      (byNode[name] = byNode[name] || []).push(it);
    }
    return { byNode, shared };
  }, [openItems]);

  const renderSection = (name: string, list: BackendReviewItem[]) => {
    const keys = list.map((i) => i.key);
    const allSelected = keys.length > 0 && keys.every((k) => selected.includes(k));
    return (
      <div key={name} className="mb-3 border border-[var(--line)] p-3">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <b className="text-sm">{name}</b>
          <div className="flex items-center gap-2">
            <span className="text-xs text-[var(--muted)]">{keys.length} unresolved</span>
            {keys.length > 0 && (
              <button
                disabled={busy}
                onClick={() => onSelectKeys(keys, !allSelected)}
                className="btn sm"
              >
                {allSelected ? 'Deselect all in file' : 'Select all in file'}
              </button>
            )}
            {keys.length > 0 && (
              <button
                disabled={busy}
                onClick={() => onDecide(list.map((i) => ({
                  key: i.key, decision: 'APPROVED', fact: readFact(i.key, i.suggested_fact || undefined),
                })).filter((d) => d.fact))}
                className="btn sm"
                title="Approve every unresolved line in this configuration that has a fact"
              >
                Approve all in file
              </button>
            )}
          </div>
        </div>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th></th>
                <th>Raw line</th>
                <th>Canonical fact</th>
                <th>Category</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((item) => (
                <tr key={item.key}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.includes(item.key)}
                      onChange={() => onToggle(item.key)}
                    />
                  </td>
                  <td className="mono text-xs">{item.raw_text || item.raw_path}</td>
                  <td className="text-xs">
                    <input
                      id={factInputId(item.key)}
                      defaultValue={item.suggested_fact || ''}
                      placeholder="Fact parameter name"
                      className="w-full min-w-40 rounded border border-[var(--line)] bg-[var(--card)] p-1.5 text-xs"
                    />
                    {item.suggested_by && (
                      <span className="text-[10px] text-[var(--muted)]">suggested by {item.suggested_by}</span>
                    )}
                  </td>
                  <td className="text-xs">{item.category_label || item.category}</td>
                  <td>
                    <div className="flex gap-1.5">
                      <button
                        disabled={busy}
                        onClick={() => onDecide([{
                          key: item.key, decision: 'APPROVED',
                          fact: readFact(item.key, item.suggested_fact || undefined),
                        }])}
                        className="btn sm success"
                      >
                        Approve
                      </button>
                      <button
                        disabled={busy}
                        onClick={() => onDecide([{ key: item.key, decision: 'REJECTED' }])}
                        className="btn sm danger"
                      >
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const nodeNames = Object.keys(sections.byNode).sort();
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 pb-3">
        <button
          disabled={busy || selected.length === 0}
          onClick={() => onDecide(selected.map((key) => {
            const item = openItems.find((i) => i.key === key);
            return { key, decision: 'APPROVED', fact: readFact(key, item?.suggested_fact || undefined) };
          }).filter((d) => d.fact))}
          className="btn sm success"
        >
          Approve selected ({selected.length})
        </button>
        <button
          disabled={busy || selected.length === 0}
          onClick={() => onDecide(selected.map((key) => ({ key, decision: 'REJECTED' })))}
          className="btn sm danger"
        >
          Reject selected
        </button>
        <button
          disabled={busy}
          onClick={() => onSelectKeys(
            openItems.filter((i) => i.suggested_fact).map((i) => i.key), true,
          )}
          className="btn sm"
        >
          Select all with suggestions
        </button>
        <button
          disabled={busy || selected.length === 0}
          onClick={() => onDismiss(selected)}
          className="btn sm"
          title="Clear stale items deliberately. A dismissal is not a rejection and records no mapping."
        >
          Dismiss selected
        </button>
      </div>

      {nodeNames.map((name) => renderSection(name, sections.byNode[name]))}
      {sections.shared.length > 0 && renderSection('Shared across configurations', sections.shared)}
    </div>
  );
}
