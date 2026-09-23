import { useEffect } from 'react';
import type { AssetReport, Report } from '../types';
import { THREAT_LABEL, assetTypeLabel, bytes, componentName, titleCase, where, years } from '../format';
import { Bar, Icon, TierBadge } from '../ui';

export function AssetDrawer({ item, report, onClose, onOpen }: { item: AssetReport; report: Report; onClose: () => void; onOpen: (id: string) => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const { asset, context, assessment: a, recommendation: r } = item;
  const m = a.mosca;
  const dependencies = (asset.dependsOn ?? []).map((id) => report.assets.find((x) => x.asset.id === id)).filter((x): x is AssetReport => Boolean(x));
  const dependents = report.assets.filter((x) => x.asset.dependsOn?.includes(asset.id));

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="asset-title">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <TierBadge tier={a.tier} />
          <span className="chip">{assetTypeLabel(asset.finding)}</span>
          <span className="chip">priority {a.priority}</span>
          <span style={{ flex: 1 }} />
          <button className="btn" onClick={onClose} aria-label="Close">
            <Icon name="close" />
          </button>
        </div>
        <h2 id="asset-title">{item.name}</h2>
        <div className="mono faint">
          {componentName(asset.component, report.subject)} · {asset.id}
        </div>

        <div className={`callout ${a.brokenNow || m.urgent ? 'danger' : ''}`} style={{ marginTop: 16 }}>
          <strong>
            {r.action === 'retain' ? 'Keep' : titleCase(r.action)}: {r.target}
          </strong>
          <div className="muted" style={{ marginTop: 4 }}>
            {r.rationale}
          </div>
          {r.sizeDelta && (
            <div style={{ marginTop: 6 }} className="mono">
              {bytes(r.sizeDelta.beforeBytes)} → {bytes(r.sizeDelta.afterBytes)}
              <span className="faint"> ({r.sizeDelta.basis})</span>
            </div>
          )}
        </div>

        <div className="section">
          <h3>Why this priority</h3>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {a.priorityReasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </div>

        <div className="section">
          <h3>Mosca's inequality</h3>
          <MoscaBar item={item} report={report} />
          <dl className="kv" style={{ marginTop: 10 }}>
            <dt>X · secrecy</dt>
            <dd>
              {years(m.xYears)} <span className="faint">{m.xReason}</span>
            </dd>
            <dt>Y · migration</dt>
            <dd>
              {years(m.yYears)} <span className="faint">from crypto-agility {a.agility.score}/100</span>
            </dd>
            <dt>Z · Q-day</dt>
            <dd>
              {years(m.zEarliestYears)} – {years(m.zLatestYears)} <span className="faint">(policy window {report.provenance.qDayEarliest}–{report.provenance.qDayLatest})</span>
            </dd>
            <dt>Verdict</dt>
            <dd style={{ color: m.urgentEvenIfLate ? 'var(--critical)' : m.urgent ? 'var(--high)' : 'var(--safe)' }}>{m.verdict}</dd>
          </dl>
        </div>

        <div className="section">
          <h3>
            {a.indexKind === 'hndl' ? 'Harvest-now-decrypt-later index' : 'Trust-now-forge-later index'} · {a.exposureIndex.toFixed(1)}
          </h3>
          <div className="faint" style={{ marginBottom: 6 }}>
            100 × {a.indexTerms.map((t) => titleCase(t.name).toLowerCase()).join(' × ')}
          </div>
          {a.indexTerms.map((t) => (
            <div className="term" key={t.name}>
              <span>{titleCase(t.name)}</span>
              <span className="mono">{t.value.toFixed(2)}</span>
              <span className="muted">{t.reason}</span>
            </div>
          ))}
        </div>

        <div className="section">
          <h3>Standing</h3>
          <dl className="kv">
            <dt>Threat</dt>
            <dd>{THREAT_LABEL[a.threat]}</dd>
            <dt>Quantum</dt>
            <dd>
              breakability {a.quantumBreakability.toFixed(1)} <span className="faint">{a.quantumReason}</span>
            </dd>
            <dt>Classical</dt>
            <dd>
              <span className={`chip ${a.classicalStatus === 'acceptable' ? 'safe' : a.classicalStatus === 'legacy' ? 'warn' : 'danger'}`}>{a.classicalStatus}</span>
              {a.classicalReasons.map((reason) => (
                <div key={reason} className="faint">
                  {reason}
                </div>
              ))}
            </dd>
            <dt>Liveness</dt>
            <dd>
              {asset.liveness} <span className="faint">{asset.livenessReason}</span>
            </dd>
            <dt>Evidence grade</dt>
            <dd>
              {asset.evidenceGrade} <span className="faint">{asset.gradeReason}</span>
            </dd>
          </dl>
        </div>

        <div className="section">
          <h3>Exposure</h3>
          {context.reachable && context.entry ? (
            <div className="path">
              <span className="step entry">{context.entry.detail}</span>
              {context.path.map((step, i) => (
                <span key={`${step}-${i}`} style={{ display: 'contents' }}>
                  <span className="arrow">→</span>
                  <span className="step">{step}</span>
                </span>
              ))}
              <span className="arrow">→</span>
              <span className="step asset">{item.name}</span>
            </div>
          ) : null}
          <p className="muted" style={{ marginBottom: 0 }}>
            exposure {context.exposure.toFixed(1)}: {context.exposureReason}
          </p>
        </div>

        <div className="section">
          <h3>Data protected</h3>
          <dl className="kv">
            <dt>Class</dt>
            <dd>
              {context.data.class} · {years(context.data.secrecyLifetimeYears)} secrecy · {context.data.criticality}
              {context.dataInherited && <span className="faint"> (inherited from the component)</span>}
            </dd>
            <dt>Confidence</dt>
            <dd>
              <div style={{ maxWidth: 200 }}>
                <Bar value={context.data.confidence} />
              </div>
            </dd>
            <dt>Evidence</dt>
            <dd>
              {context.data.matches.length === 0 && <span className="faint">{context.data.explanation}</span>}
              {context.data.matches.map((match) => (
                <div key={`${match.source}-${match.name}`}>
                  <span className="chip">{match.source}</span> <code>{match.name}</code> <span className="faint">matches</span> <code>{match.term}</code>
                </div>
              ))}
            </dd>
          </dl>
        </div>

        <div className="section">
          <h3>Crypto-agility · {a.agility.score}/100</h3>
          {a.agility.factors.map((f) => (
            <div className="term" key={f.name}>
              <span>{titleCase(f.name)}</span>
              <span className="mono">
                {f.points}/{f.max}
              </span>
              <span className="muted">{f.reason}</span>
            </div>
          ))}
        </div>

        {(dependencies.length > 0 || dependents.length > 0) && (
          <div className="section">
            <h3>Related assets</h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {dependencies.map((d) => (
                <button key={d.asset.id} className="btn" onClick={() => onOpen(d.asset.id)}>
                  uses {d.name}
                </button>
              ))}
              {dependents.map((d) => (
                <button key={d.asset.id} className="btn" onClick={() => onOpen(d.asset.id)}>
                  used by {d.name}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="section">
          <h3>Evidence · {asset.occurrences.length} occurrence{asset.occurrences.length === 1 ? '' : 's'}</h3>
          <div className="table-wrap">
            <table className="data" style={{ cursor: 'default' }}>
              <thead>
                <tr>
                  <th>Where</th>
                  <th>Surface</th>
                  <th>Rule</th>
                  <th>API</th>
                </tr>
              </thead>
              <tbody>
                {asset.occurrences.map((o, i) => (
                  <tr key={i} style={{ cursor: 'default' }}>
                    <td className="mono">{where(o.location)}</td>
                    <td>{o.surface}</td>
                    <td className="mono faint">
                      {o.evidence.ruleId}
                      <div>{o.evidence.kind}</div>
                    </td>
                    <td className="mono">
                      {o.usage?.api ?? o.evidence.matchedToken}
                      {o.usage?.function && <div className="faint">in {o.usage.function.split('::').pop()}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </aside>
    </>
  );
}

function MoscaBar({ item, report }: { item: AssetReport; report: Report }) {
  const m = item.assessment.mosca;
  const horizon = Math.max(m.zLatestYears + 3, Math.ceil(m.xYears + m.yYears) + 1);
  const pos = (v: number) => `${(v / horizon) * 100}%`;
  const start = report.provenance.assessmentYear;
  return (
    <div>
      <div style={{ position: 'relative', height: 26, background: 'var(--bg-sunken)', borderRadius: 6, border: '1px solid var(--border)', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', left: pos(m.zEarliestYears), width: `calc(${pos(m.zLatestYears)} - ${pos(m.zEarliestYears)})`, top: 0, bottom: 0, background: 'var(--qday)', borderLeft: '1px dashed var(--qday-edge)' }} />
        <div style={{ position: 'absolute', left: 0, width: pos(m.xYears), top: 7, height: 12, background: 'var(--accent)', borderRadius: 3 }} />
        <div style={{ position: 'absolute', left: pos(m.xYears), width: pos(m.yYears), top: 7, height: 12, background: 'var(--accent-2)', borderRadius: 3 }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between' }} className="faint">
        <span>{start}</span>
        <span>{start + horizon}</span>
      </div>
    </div>
  );
}
