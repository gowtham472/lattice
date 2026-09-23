import type { ReactNode } from 'react';
import type { Tier } from './types';

export function TierBadge({ tier }: { tier: Tier }) {
  return <span className={`tier tier-${tier}`}>{tier}</span>;
}

export function Panel({ title, hint, actions, children }: { title?: string; hint?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      {title && (
        <div className="panel-head">
          <h2>{title}</h2>
          {hint && <span className="hint">{hint}</span>}
          {actions && <span style={{ marginLeft: 'auto' }}>{actions}</span>}
        </div>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="panel kpi">
      <div className="label">{label}</div>
      <div className="value" style={tone ? { color: `var(--${tone})` } : undefined}>
        {value}
      </div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

export function Bar({ value, max = 1 }: { value: number; max?: number }) {
  const width = max > 0 ? Math.max(0, Math.min(1, value / max)) * 100 : 0;
  return (
    <div className="bar" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max}>
      <span style={{ width: `${width}%` }} />
    </div>
  );
}

const ICONS: Record<string, string> = {
  overview: 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
  inventory: 'M4 6h16M4 12h16M4 18h16',
  graph: 'M6 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M18 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M12 18m-2 0a2 2 0 1 0 4 0a2 2 0 1 0-4 0M8 6h8M7 8l4 8M17 8l-4 8',
  roadmap: 'M4 19V5M4 5h11l-2 4 2 4H4',
  compare: 'M8 3v18M16 3v18M3 8h5M16 16h5',
  scans: 'M4 7V4h3M20 7V4h-3M4 17v3h3M20 17v3h-3M4 12h16',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6',
  close: 'M6 6l12 12M18 6L6 18',
  sun: 'M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6 4.2 4.2M19.8 19.8l-1.4-1.4M5.6 18.4l-1.4 1.4M19.8 4.2l-1.4 1.4M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8',
};

export function Icon({ name, size = 16 }: { name: keyof typeof ICONS | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICONS[name] ?? ''} />
    </svg>
  );
}

export function Logo() {
  return (
    <svg width={30} height={30} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="var(--bg-raised)" stroke="var(--border-strong)" />
      <g stroke="var(--accent)" strokeWidth="2" fill="none">
        <path d="M8 8h16v16H8z" />
        <path d="M8 16h16M16 8v16" />
      </g>
      <g fill="var(--accent-2)">
        <circle cx="8" cy="8" r="2.4" />
        <circle cx="24" cy="24" r="2.4" />
        <circle cx="16" cy="16" r="2.4" />
      </g>
    </svg>
  );
}
