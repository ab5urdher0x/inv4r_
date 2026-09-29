import React, { useEffect, useRef, useState } from 'react';
import { infoFor } from '../data/infoCopy';

interface Props {
  id: string;
  align?: 'left' | 'right';
}

export function SectionInfo({ id, align = 'left' }: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement | null>(null);
  const copy = infoFor(id);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  if (!copy) return null;

  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        type="button"
        aria-label="Section information"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="info-btn"
      >
        i
      </button>
      {open && (
        <div
          role="dialog"
          className="info-pop"
          style={{ [align === 'right' ? 'right' : 'left']: 0 } as React.CSSProperties}
        >
          <span>{copy}</span>
          <button type="button" className="info-pop-close" aria-label="Dismiss" onClick={() => setOpen(false)}>
            ✕
          </button>
        </div>
      )}
    </span>
  );
}
