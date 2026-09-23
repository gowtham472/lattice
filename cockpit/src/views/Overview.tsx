import { useMemo } from 'react';
import type { AssetReport, Report, Threat, Tier } from '../types';
import { THREAT_LABEL, TIERS, componentName, primaryLocation, years } from '../format';
import { Kpi, Panel, TierBadge } from '../ui';

export function Overview({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const s = report.summary;
  const pqReady = report.assets.filter((a) => a.assessment.quantumBreakability === 0).length;
  const confirmed = report.assets.filter((a) => a.asset.liveness === 'Confirmed').length;

  return (
    <div className="grid">
      <div className="kpis">
        <Kpi label="Cryptographic assets" value={s.assets} sub={`${report.stats.filesScanned} files · ${report.graph.entryPoints} entry points`} />
        <Kpi label="Quantum-vulnerable" value={s.quantumVulnerable} tone="high" sub={`${pqReady} already post-quantum`} />
        <Kpi label="Mosca-urgent" value={s.moscaUrgent} tone="critical" sub="X + Y exceeds the earliest Q-day" />
        <Kpi label="Broken today" value={s.brokenNow} tone="critical" sub="no quantum computer needed" />
        <Kpi label="Critical · High" value={`${s.critical} · ${s.high}`} sub={`${confirmed} confirmed reachable`} />
      </div>

      <MoscaTimeline report={report} onOpen={onOpen} />

      <div className="two-col">
        <Heatmap report={report} />
        <div className="grid">
          <ThreatSplit report={report} />
          <TopRisks report={report} onOpen={onOpen} />
        </div>
      </div>
    </div>
  );
}

/**
 * Mosca's inequality, per asset: X (how long the data must stay secret) followed by Y (how long
 * migration will take), against the Q-day window. A bar that reaches into the window is urgent;
 * one that passes the window's far edge is already late.
 */
function MoscaTimeline({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const { assessmentYear, qDayEarliest, qDayLatest } = report.provenance;
  const rows = useMemo(
    () =>
      report.assets
        .filter((a) => a.assessment.mosca.applicable)
        .sort((a, b) => b.assessment.mosca.xYears + b.assessment.mosca.yYears - (a.assessment.mosca.xYears + a.assessment.mosca.yYears) || b.assessment.priority - a.assessment.priority)
        .slice(0, 16),
    [report],
  );
  if (rows.length === 0) {
    return (
      <Panel title="Mosca timeline">
        <div className="empty">No quantum-vulnerable assets: nothing to migrate before Q-day.</div>
      </Panel>
    );
  }
  const horizon = Math.max(qDayLatest - assessmentYear + 4, ...rows.map((r) => Math.ceil(r.assessment.mosca.xYears + r.assessment.mosca.yYears)));
  const labelWidth = 250;
  const width = 1000;
  const rowHeight = 26;
  const top = 44;
  const plot = width - labelWidth - 150; // room for the verdict after the longest bar
  const x = (yearsFromNow: number) => labelWidth + (yearsFromNow / horizon) * plot;
  const height = top + rows.length * rowHeight + 12;
  const ticks = Array.from({ length: Math.floor(horizon / 2) + 1 }, (_, i) => i * 2);

  return (
    <Panel
      title="Mosca timeline"
      hint={
        <>
          X (secrecy) <span style={{ color: 'var(--accent)' }}>■</span> + Y (migration) <span style={{ color: 'var(--accent-2)' }}>■</span> against the Q-day window{' '}
          {qDayEarliest}–{qDayLatest}
        </>
      }
    >
      <div style={{ overflowX: 'auto' }}>
        <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: 720 }} role="img" aria-label="Mosca timeline">
          <rect x={x(qDayEarliest - assessmentYear)} y={top - 8} width={x(qDayLatest - assessmentYear) - x(qDayEarliest - assessmentYear)} height={height - top} fill="var(--qday)" />
          <line x1={x(qDayEarliest - assessmentYear)} x2={x(qDayEarliest - assessmentYear)} y1={top - 8} y2={height - 4} stroke="var(--qday-edge)" strokeDasharray="4 3" />
          <text x={x(qDayEarliest - assessmentYear) + 4} y={top - 12} fontSize="11" fill="var(--critical)">
            Q-day window
          </text>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={x(t)} x2={x(t)} y1={18} y2={height - 4} stroke="var(--border)" />
              <text x={x(t)} y={12} fontSize="10.5" textAnchor="middle" fill="var(--text-faint)">
                {assessmentYear + t}
              </text>
            </g>
          ))}
          {rows.map((row, i) => {
            const m = row.assessment.mosca;
            const y = top + i * rowHeight;
            return (
              <g key={row.asset.id} style={{ cursor: 'pointer' }} onClick={() => onOpen(row.asset.id)}>
                <title>{`${row.name}: ${m.verdict}`}</title>
                <text x={8} y={y + 15} fontSize="12" fill="var(--text)">
                  {truncate(row.name, 22)}
                </text>
                <text x={labelWidth - 10} y={y + 15} fontSize="11" textAnchor="end" fill="var(--text-faint)">
                  {truncate(componentName(row.asset.component, report.subject), 14)}
                </text>
                <rect x={x(0)} y={y + 5} width={Math.max(1, x(m.xYears) - x(0))} height={13} rx={3} fill="var(--accent)" opacity={0.85} />
                <rect x={x(m.xYears)} y={y + 5} width={Math.max(1, x(m.xYears + m.yYears) - x(m.xYears))} height={13} rx={3} fill="var(--accent-2)" opacity={0.85} />
                <text x={x(m.xYears + m.yYears) + 6} y={y + 15} fontSize="11" fill={m.urgentEvenIfLate ? 'var(--critical)' : m.urgent ? 'var(--high)' : 'var(--safe)'}>
                  {years(m.xYears + m.yYears)} {m.urgentEvenIfLate ? '· already late' : m.urgent ? '· migrate now' : '· fits'}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </Panel>
  );
}

function truncate(text: string, length: number) {
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function Heatmap({ report }: { report: Report }) {
  const rows = useMemo(() => {
    const byComponent = new Map<string, Record<Tier, number>>();
    for (const a of report.assets) {
      const key = componentName(a.asset.component, report.subject);
      const counts = byComponent.get(key) ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      counts[a.assessment.tier] += 1;
      byComponent.set(key, counts);
    }
    return [...byComponent.entries()].sort(([, a], [, b]) => score(b) - score(a));
  }, [report]);
  const max = Math.max(1, ...rows.flatMap(([, c]) => Object.values(c)));

  return (
    <Panel title="Risk by component" hint="assets per tier">
      <div className="table-wrap">
        <table className="data" style={{ cursor: 'default' }}>
          <thead>
            <tr>
              <th>Component</th>
              {TIERS.map((t) => (
                <th key={t} className="num">
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(([component, counts]) => (
              <tr key={component} style={{ cursor: 'default' }}>
                <td className="mono">{component}</td>
                {TIERS.map((t) => (
                  <td key={t} className="num" style={{ background: counts[t] ? `color-mix(in srgb, var(--${t}) ${12 + (counts[t] / max) * 50}%, transparent)` : undefined, fontWeight: counts[t] ? 600 : 400 }}>
                    {counts[t] || <span className="faint">·</span>}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function score(counts: Record<Tier, number>) {
  return counts.critical * 1000 + counts.high * 100 + counts.medium * 10 + counts.low;
}

function ThreatSplit({ report }: { report: Report }) {
  const threats: Threat[] = ['harvest', 'forge', 'integrity'];
  const vulnerable = report.assets.filter((a) => a.assessment.quantumBreakability >= 0.5 || a.assessment.brokenNow);
  const total = Math.max(1, vulnerable.length);
  const colors: Record<Threat, string> = { harvest: 'var(--critical)', forge: 'var(--high)', integrity: 'var(--accent-2)' };
  return (
    <Panel title="What the attacker gets" hint="vulnerable assets by threat">
      <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', background: 'var(--bg-sunken)' }}>
        {threats.map((t) => {
          const n = vulnerable.filter((a) => a.assessment.threat === t).length;
          return n ? <span key={t} style={{ width: `${(n / total) * 100}%`, background: colors[t] }} /> : null;
        })}
      </div>
      <div className="grid" style={{ gap: 6, marginTop: 12 }}>
        {threats.map((t) => (
          <div key={t} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: colors[t] }} />
            <span style={{ flex: 1 }}>{THREAT_LABEL[t]}</span>
            <strong>{vulnerable.filter((a) => a.assessment.threat === t).length}</strong>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function TopRisks({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const top: AssetReport[] = report.assets.slice(0, 6);
  return (
    <Panel title="Fix first" hint="highest priority">
      <div className="grid" style={{ gap: 8 }}>
        {top.map((a) => (
          <button key={a.asset.id} className="card" onClick={() => onOpen(a.asset.id)} style={{ textAlign: 'left' }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <TierBadge tier={a.assessment.tier} />
              <strong style={{ flex: 1 }}>{a.name}</strong>
              <span className="faint">{a.assessment.priority}</span>
            </div>
            <span className="mono faint">{primaryLocation(a)}</span>
            <span className="muted">
              {a.recommendation.action} → {a.recommendation.target}
            </span>
          </button>
        ))}
      </div>
    </Panel>
  );
}
