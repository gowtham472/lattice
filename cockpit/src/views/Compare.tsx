import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Comparison, ScanMeta, Tier } from '../types';
import { when } from '../format';
import { Panel, TierBadge } from '../ui';

export function Compare({ scans, onError }: { scans: ScanMeta[]; onError: (e: unknown) => void }) {
  const done = scans.filter((s) => s.status === 'done');
  const [baseline, setBaseline] = useState(done[1]?.id ?? '');
  const [current, setCurrent] = useState(done[0]?.id ?? '');
  const [failOn, setFailOn] = useState<Tier>('high');
  const [result, setResult] = useState<Comparison | null>(null);

  useEffect(() => {
    setResult(null);
    if (!baseline || !current || baseline === current) return;
    let cancelled = false;
    api
      .compare(baseline, current, failOn)
      .then((r) => !cancelled && setResult(r))
      .catch(onError);
    return () => {
      cancelled = true;
    };
  }, [baseline, current, failOn, onError]);

  const option = (s: ScanMeta) => (
    <option key={s.id} value={s.id}>
      {s.subject} · {when(s.requested)}
    </option>
  );
  const regressions = result?.changes.filter((c) => c.regression).length ?? 0;

  return (
    <div className="grid">
      <Panel title="Compare two scans" hint="the same check `lattice ci` runs in a pipeline">
        {done.length < 2 ? (
          <div className="empty">Run at least two scans to compare them.</div>
        ) : (
          <div className="filters">
            <label className="muted">Baseline</label>
            <select className="select" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
              {done.map(option)}
            </select>
            <label className="muted">Current</label>
            <select className="select" value={current} onChange={(e) => setCurrent(e.target.value)}>
              {done.map(option)}
            </select>
            <label className="muted">Fail on</label>
            <select className="select" value={failOn} onChange={(e) => setFailOn(e.target.value as Tier)}>
              <option value="critical">critical</option>
              <option value="high">high and above</option>
              <option value="medium">medium and above</option>
              <option value="low">low and above</option>
            </select>
          </div>
        )}
        {baseline && baseline === current && <div className="faint">Pick two different scans.</div>}
        {(() => {
          const [a, b] = [done.find((s) => s.id === baseline), done.find((s) => s.id === current)];
          return a && b && (a.root !== b.root || a.path !== b.path) ? (
            <div className="callout" style={{ margin: '8px 0' }}>
              These scans cover different targets ({a.root}:{a.path || '/'} and {b.root}:{b.path || '/'}). Assets are identified per component, and components
              depend on what was scanned, so compare scans of the same target over time.
            </div>
          ) : null;
        })()}
        {result && (
          <>
            <div className={`callout ${regressions ? 'danger' : ''}`} style={{ margin: '8px 0 14px' }}>
              {regressions ? (
                <strong>
                  Gate fails: {regressions} regression{regressions === 1 ? '' : 's'} at or above {result.threshold}
                </strong>
              ) : (
                <strong>Gate passes: {result.changes.length} change{result.changes.length === 1 ? '' : 's'}, none at or above {result.threshold}</strong>
              )}
            </div>
            <div className="table-wrap">
              <table className="data" style={{ cursor: 'default' }}>
                <thead>
                  <tr>
                    <th>Gate</th>
                    <th>Change</th>
                    <th>Asset</th>
                    <th>Component</th>
                    <th>Tier</th>
                    <th>Why</th>
                  </tr>
                </thead>
                <tbody>
                  {result.changes.map((c) => (
                    <tr key={`${c.kind}-${c.bomRef}`} style={{ cursor: 'default' }}>
                      <td>{c.regression ? <span className="chip danger">fail</span> : <span className="chip">ok</span>}</td>
                      <td>{c.kind}</td>
                      <td style={{ fontWeight: 600 }}>{c.name}</td>
                      <td className="mono">{c.component}</td>
                      <td>
                        {c.previousTier && <TierBadge tier={c.previousTier} />}
                        {c.previousTier && c.tier && <span className="faint"> → </span>}
                        {c.tier && <TierBadge tier={c.tier} />}
                      </td>
                      <td className="muted">{c.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {result.changes.length === 0 && <div className="empty">No differences.</div>}
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
