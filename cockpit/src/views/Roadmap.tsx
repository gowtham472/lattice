import type { Report, RoadmapItem } from '../types';
import { componentName, years } from '../format';
import { Panel, TierBadge } from '../ui';

const WAVES: { wave: number; title: string; description: string }[] = [
  { wave: 1, title: 'Wave 1 · urgent quick wins', description: 'High or critical, and agile (score 60+): change configuration or the provider call now.' },
  { wave: 2, title: 'Wave 2 · urgent re-engineering', description: 'High or critical but hard-coded (agility under 60): start now, the change itself takes time.' },
  { wave: 3, title: 'Wave 3 · planned migration', description: 'Medium risk: schedule it into the migration programme.' },
  { wave: 4, title: 'Wave 4 · opportunistic hygiene', description: 'Low risk: fold into routine maintenance.' },
];

export function Roadmap({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const byWave = (wave: number) => report.roadmap.filter((item) => item.wave === wave);
  const retained = report.assets.length - report.roadmap.length;
  const effort = (items: RoadmapItem[]) => items.reduce((sum, item) => Math.max(sum, item.migrationYears), 0);

  return (
    <div className="grid">
      <Panel title="Migration roadmap" hint={`${report.roadmap.length} assets to change · ${retained} retained as they are`}>
        <div className="waves">
          {WAVES.map(({ wave, title, description }) => {
            const items = byWave(wave);
            return (
              <section className="wave" key={wave} aria-label={title}>
                <header>
                  <strong>{title}</strong>
                  <span className="faint" style={{ fontSize: 12 }}>
                    {description}
                  </span>
                  <span className="muted" style={{ fontSize: 12 }}>
                    {items.length} item{items.length === 1 ? '' : 's'}
                    {items.length > 0 && ` · longest ${years(effort(items))}`}
                  </span>
                </header>
                {items.map((item) => (
                  <button className="card" key={item.assetId} onClick={() => onOpen(item.assetId)} style={{ textAlign: 'left' }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <TierBadge tier={item.tier} />
                      <strong style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name}</strong>
                    </div>
                    <span className="mono faint">{componentName(item.component, report.subject)}</span>
                    <span>
                      <span className="muted">{item.action} →</span> {item.target}
                    </span>
                    <span className="faint" style={{ fontSize: 12 }}>
                      agility {item.agility}/100 · ~{years(item.migrationYears)} to migrate
                    </span>
                  </button>
                ))}
                {items.length === 0 && <span className="faint">Nothing in this wave.</span>}
              </section>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
