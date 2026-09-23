import { useMemo, useState } from 'react';
import type { AssetReport, Report, Threat, Tier } from '../types';
import { THREAT_SHORT, TIERS, assetTypeLabel, componentName, primaryLocation } from '../format';
import { Panel, TierBadge } from '../ui';

type SortKey = 'priority' | 'name' | 'component' | 'index' | 'agility' | 'mosca';

export function Inventory({ report, selected, onOpen }: { report: Report; selected: string | null; onOpen: (id: string) => void }) {
  const [query, setQuery] = useState('');
  const [tier, setTier] = useState<Tier | ''>('');
  const [threat, setThreat] = useState<Threat | ''>('');
  const [component, setComponent] = useState('');
  const [type, setType] = useState('');
  const [onlyReachable, setOnlyReachable] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean }>({ key: 'priority', descending: true });

  const components = useMemo(() => [...new Set(report.assets.map((a) => a.asset.component))].sort(), [report]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = report.assets.filter(
      (a) =>
        (!tier || a.assessment.tier === tier) &&
        (!threat || a.assessment.threat === threat) &&
        (!component || a.asset.component === component) &&
        (!type || a.asset.finding.assetType === type) &&
        (!onlyReachable || a.context.reachable) &&
        (!needle || `${a.name} ${primaryLocation(a)} ${a.recommendation.target} ${a.context.data.class}`.toLowerCase().includes(needle)),
    );
    const value = (a: AssetReport): number | string => {
      switch (sort.key) {
        case 'priority':
          return a.assessment.priority;
        case 'name':
          return a.name.toLowerCase();
        case 'component':
          return a.asset.component;
        case 'index':
          return a.assessment.exposureIndex;
        case 'agility':
          return a.assessment.agility.score;
        case 'mosca':
          return a.assessment.mosca.applicable ? a.assessment.mosca.urgencyYears : -99;
      }
    };
    return filtered.sort((a, b) => {
      const [x, y] = [value(a), value(b)];
      const order = x < y ? -1 : x > y ? 1 : 0;
      return sort.descending ? -order : order;
    });
  }, [report, query, tier, threat, component, type, onlyReachable, sort]);

  const header = (key: SortKey, label: string, numeric = false) => (
    <th
      className={`sortable ${numeric ? 'num' : ''}`}
      onClick={() => setSort((s) => ({ key, descending: s.key === key ? !s.descending : key !== 'name' && key !== 'component' }))}
      aria-sort={sort.key === key ? (sort.descending ? 'descending' : 'ascending') : 'none'}
    >
      {label}
      {sort.key === key ? (sort.descending ? ' ↓' : ' ↑') : ''}
    </th>
  );

  return (
    <Panel title={`${rows.length} of ${report.assets.length} assets`} hint="click a row for the full explanation">
      <div className="filters">
        <input className="input" style={{ flex: '1 1 220px' }} placeholder="Search name, file, target, data class…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search" />
        <select className="select" value={tier} onChange={(e) => setTier(e.target.value as Tier | '')} aria-label="Tier">
          <option value="">All tiers</option>
          {TIERS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select className="select" value={threat} onChange={(e) => setThreat(e.target.value as Threat | '')} aria-label="Threat">
          <option value="">All threats</option>
          <option value="harvest">Harvest now, decrypt later</option>
          <option value="forge">Forgery</option>
          <option value="integrity">Integrity</option>
        </select>
        <select className="select" value={type} onChange={(e) => setType(e.target.value)} aria-label="Asset type">
          <option value="">All types</option>
          <option value="algorithm">Algorithms</option>
          <option value="certificate">Certificates</option>
          <option value="protocol">Protocols</option>
          <option value="related-crypto-material">Key material</option>
        </select>
        <select className="select" value={component} onChange={(e) => setComponent(e.target.value)} aria-label="Component">
          <option value="">All components</option>
          {components.map((c) => (
            <option key={c} value={c}>
              {componentName(c, report.subject)}
            </option>
          ))}
        </select>
        <label style={{ display: 'flex', gap: 6, alignItems: 'center' }} className="muted">
          <input type="checkbox" checked={onlyReachable} onChange={(e) => setOnlyReachable(e.target.checked)} />
          reachable only
        </label>
      </div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Tier</th>
              {header('priority', 'Pri', true)}
              {header('name', 'Asset')}
              {header('component', 'Component')}
              <th>Threat</th>
              <th>Exposure</th>
              <th>Data</th>
              {header('index', 'Index', true)}
              {header('agility', 'Agility', true)}
              {header('mosca', 'Mosca')}
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const m = a.assessment.mosca;
              return (
                <tr key={a.asset.id} className={selected === a.asset.id ? 'selected' : ''} onClick={() => onOpen(a.asset.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onOpen(a.asset.id)}>
                  <td>
                    <TierBadge tier={a.assessment.tier} />
                  </td>
                  <td className="num">{a.assessment.priority}</td>
                  <td style={{ minWidth: 220, maxWidth: 360 }}>
                    <div style={{ fontWeight: 600 }}>{a.name}</div>
                    <div className="faint" style={{ fontSize: 12 }}>
                      {assetTypeLabel(a.asset.finding)}
                    </div>
                    <div className="mono faint" style={{ overflowWrap: 'anywhere' }}>
                      {primaryLocation(a)}
                    </div>
                  </td>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                    {componentName(a.asset.component, report.subject)}
                  </td>
                  <td>
                    {a.assessment.brokenNow ? <span className="chip danger">broken now</span> : a.assessment.quantumBreakability === 0 ? <span className="chip safe">PQ-safe</span> : <span className="chip">{THREAT_SHORT[a.assessment.threat]}</span>}
                  </td>
                  <td>
                    <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
                      {a.context.entry ? <span className="chip warn">{a.context.entry.kind}</span> : !a.context.reachable && <span className="faint">not reached</span>}
                      {a.asset.surfaces.includes('runtime') && (
                        <span className="chip live" title="negotiated in captured network traffic">
                          on the wire
                        </span>
                      )}
                    </span>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {a.context.data.class}
                    <span className="faint"> · {a.context.data.secrecyLifetimeYears}y</span>
                  </td>
                  <td className="num" style={{ whiteSpace: 'nowrap' }}>
                    {a.assessment.exposureIndex.toFixed(0)}
                    <span className="faint"> {a.assessment.indexKind}</span>
                  </td>
                  <td className="num">{a.assessment.agility.score}</td>
                  <td>{!m.applicable ? <span className="chip safe">n/a</span> : m.urgentEvenIfLate ? <span className="chip danger">late</span> : m.urgent ? <span className="chip warn">urgent</span> : <span className="chip">fits</span>}</td>
                  <td style={{ minWidth: 260 }}>
                    <span className="muted">{a.recommendation.action}</span> {a.recommendation.target}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty">No assets match these filters.</div>}
      </div>
    </Panel>
  );
}
