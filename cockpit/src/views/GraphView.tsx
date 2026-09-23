import { useMemo, useState } from 'react';
import type { Graph, GraphNode, Report, Tier } from '../types';
import { componentName } from '../format';
import { Panel } from '../ui';

interface LaidOut {
  id: string;
  column: number;
  label: string;
  sub?: string;
  color: string;
  assetId?: string;
  dim?: boolean;
}

const COLUMN_WIDTH = 230;
const ROW_HEIGHT = 34;
const NODE_WIDTH = 190;
const NODE_HEIGHT = 24;
const MAX_FUNCTION_DEPTH = 3;

const ENTRY_COLOR: Record<string, string> = {
  'http-route': 'var(--high)',
  listener: 'var(--high)',
  'library-export': 'var(--medium)',
  main: 'var(--info)',
};

export function GraphView({ report, graph, onOpen }: { report: Report; graph: Graph; onOpen: (id: string) => void }) {
  const [component, setComponent] = useState('');
  const [reachableOnly, setReachableOnly] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);

  const tierOf = useMemo(() => new Map(report.assets.map((a) => [a.asset.id, a.assessment.tier] as [string, Tier])), [report]);
  const componentOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const e of graph.edges) if (e.kind === 'contains') map.set(e.target, e.source.replace(/^component\//, ''));
    return map;
  }, [graph]);
  const components = useMemo(() => [...new Set(componentOf.values())].sort(), [componentOf]);

  const layout = useMemo(() => {
    const byId = new Map(graph.nodes.map((n) => [n.id, n] as [string, GraphNode]));
    const outgoing = new Map<string, string[]>();
    const link = (from: string, to: string) => outgoing.set(from, [...(outgoing.get(from) ?? []), to]);
    const edges: [string, string][] = [];
    const dataClassOf = (id: string) => {
      const node = byId.get(id);
      return node?.type === 'data' ? `class/${node.class}` : id;
    };
    for (const e of graph.edges) {
      if (e.kind === 'exposes' || e.kind === 'calls' || e.kind === 'uses') {
        link(e.source, e.target);
        edges.push([e.source, e.target]);
      } else if (e.kind === 'protects') {
        edges.push([e.source, dataClassOf(e.target)]);
      }
    }

    // call depth from the entry points
    const depth = new Map<string, number>();
    const queue: string[] = [];
    for (const n of graph.nodes) if (n.type === 'entry') {
      depth.set(n.id, 0);
      queue.push(n.id);
    }
    while (queue.length) {
      const id = queue.shift()!;
      for (const next of outgoing.get(id) ?? []) {
        if (byId.get(next)?.type === 'function' && !depth.has(next)) {
          depth.set(next, Math.min((depth.get(id) ?? 0) + 1, MAX_FUNCTION_DEPTH));
          queue.push(next);
        }
      }
    }
    const reached = new Set<string>(depth.keys());
    for (const [from, to] of edges) if (reached.has(from) && byId.get(to)?.type === 'crypto') reached.add(to);

    // keep only what leads to cryptography
    const incoming = new Map<string, string[]>();
    for (const [from, to] of edges) incoming.set(to, [...(incoming.get(to) ?? []), from]);
    const relevant = new Set<string>();
    const stack = graph.nodes.filter((n) => n.type === 'crypto').map((n) => n.id);
    while (stack.length) {
      const id = stack.pop()!;
      if (relevant.has(id)) continue;
      relevant.add(id);
      for (const from of incoming.get(id) ?? []) if (byId.get(from)?.type !== 'crypto') stack.push(from);
    }

    const keep = (n: GraphNode) => {
      if (n.type === 'component' || n.type === 'library' || n.type === 'data') return false;
      if (!relevant.has(n.id)) return false;
      if (component && componentOf.get(n.id) !== component && n.type !== 'entry') return false;
      if (reachableOnly && !reached.has(n.id)) return false;
      return true;
    };

    const nodes: LaidOut[] = [];
    for (const n of graph.nodes) {
      if (!keep(n)) continue;
      switch (n.type) {
        case 'entry':
          nodes.push({ id: n.id, column: 0, label: n.detail, sub: n.kind, color: ENTRY_COLOR[n.kind] ?? 'var(--info)' });
          break;
        case 'function':
          nodes.push({ id: n.id, column: depth.get(n.id) ?? 1, label: n.name === '<tls-listener>' ? 'TLS listener' : n.name, sub: `${n.path}:${n.line}`, color: 'var(--text-muted)', dim: !reached.has(n.id) });
          break;
        case 'crypto': {
          const tier = tierOf.get(n.id) ?? 'info';
          nodes.push({ id: n.id, column: MAX_FUNCTION_DEPTH + 1, label: n.name, sub: componentName(componentOf.get(n.id) ?? '.', report.subject), color: `var(--${tier})`, assetId: n.id, dim: !reached.has(n.id) });
          break;
        }
      }
    }
    const shown = new Set(nodes.map((n) => n.id));
    // data classes that the shown assets protect
    const classes = new Map<string, { secrecy: number }>();
    for (const [from, to] of edges) {
      if (to.startsWith('class/') && shown.has(from)) {
        const node = graph.nodes.find((n) => n.type === 'data' && `class/${n.class}` === to);
        classes.set(to, { secrecy: node?.type === 'data' ? node.secrecyLifetimeYears : 0 });
      }
    }
    for (const [id, { secrecy }] of [...classes.entries()].sort(([, a], [, b]) => b.secrecy - a.secrecy)) {
      nodes.push({ id, column: MAX_FUNCTION_DEPTH + 2, label: id.slice(6), sub: `${secrecy} y secrecy`, color: secrecy >= 20 ? 'var(--critical)' : secrecy >= 10 ? 'var(--high)' : 'var(--accent-2)' });
      shown.add(id);
    }

    // drop empty function columns
    const used = [...new Set(nodes.map((n) => n.column))].sort((a, b) => a - b);
    const remap = new Map(used.map((c, i) => [c, i]));
    const rows = new Map<number, number>();
    const positioned = nodes
      .sort((a, b) => a.column - b.column || Number(a.dim ?? false) - Number(b.dim ?? false) || a.label.localeCompare(b.label))
      .map((n) => {
        const column = remap.get(n.column) ?? 0;
        const row = rows.get(column) ?? 0;
        rows.set(column, row + 1);
        return { ...n, column, x: 16 + column * COLUMN_WIDTH, y: 40 + row * ROW_HEIGHT };
      });
    const position = new Map(positioned.map((n) => [n.id, n]));
    const lines = [...new Set(edges.filter(([a, b]) => position.has(a) && position.has(b)).map(([a, b]) => `${a}\u0000${b}`))].map((key) => key.split('\u0000') as [string, string]);
    const height = 60 + Math.max(...[...rows.values()], 1) * ROW_HEIGHT;
    const width = 32 + used.length * COLUMN_WIDTH;
    const headers = used.map((c) => (c === 0 ? 'Entry points' : c <= MAX_FUNCTION_DEPTH ? `Functions · depth ${c}` : c === MAX_FUNCTION_DEPTH + 1 ? 'Cryptographic assets' : 'Data protected'));
    return { positioned, position, lines, width, height, headers };
  }, [graph, report, component, reachableOnly, tierOf, componentOf]);

  // everything upstream and downstream of the focused node
  const highlighted = useMemo(() => {
    if (!focus) return null;
    const set = new Set([focus]);
    const walk = (forward: boolean) => {
      const stack = [focus];
      while (stack.length) {
        const id = stack.pop()!;
        for (const [a, b] of layout.lines) {
          const [from, to] = forward ? [a, b] : [b, a];
          if (from === id && !set.has(to)) {
            set.add(to);
            stack.push(to);
          }
        }
      }
    };
    walk(true);
    walk(false);
    return set;
  }, [focus, layout.lines]);

  return (
    <Panel
      title="Exposure map"
      hint={`${report.graph.entryPoints} entry points · ${report.graph.reachableFunctions} reachable functions · ${report.graph.reachableAssets} reachable assets`}
      actions={
        <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select className="select" value={component} onChange={(e) => setComponent(e.target.value)} aria-label="Component">
            <option value="">All components</option>
            {components.map((c) => (
              <option key={c} value={c}>
                {componentName(c, report.subject)}
              </option>
            ))}
          </select>
          <label className="muted" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={reachableOnly} onChange={(e) => setReachableOnly(e.target.checked)} /> reachable only
          </label>
        </span>
      }
    >
      <div className="legend" style={{ marginBottom: 10 }}>
        <span>
          <i style={{ background: 'var(--high)' }} />
          route or listener
        </span>
        <span>
          <i style={{ background: 'var(--critical)' }} />
          critical asset
        </span>
        <span>
          <i style={{ background: 'var(--medium)' }} />
          medium
        </span>
        <span>
          <i style={{ background: 'var(--low)' }} />
          low
        </span>
        <span>
          <i style={{ background: 'var(--info)' }} />
          info
        </span>
        <span className="faint">faded: nothing we can see reaches it · hover to trace · click an asset to explain it</span>
      </div>
      <div className="graph-canvas">
        <svg width={layout.width} height={layout.height} role="img" aria-label="Crypto exposure graph">
          {layout.headers.map((h, i) => (
            <text key={h} x={16 + i * COLUMN_WIDTH} y={22} fontSize="11" fill="var(--text-faint)" style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {h}
            </text>
          ))}
          {layout.lines.map(([a, b]) => {
            const from = layout.position.get(a)!;
            const to = layout.position.get(b)!;
            const x1 = from.x + NODE_WIDTH;
            const y1 = from.y + NODE_HEIGHT / 2;
            const x2 = to.x;
            const y2 = to.y + NODE_HEIGHT / 2;
            const lit = highlighted ? highlighted.has(a) && highlighted.has(b) : false;
            return (
              <path
                key={`${a}->${b}`}
                d={`M${x1},${y1} C${x1 + 40},${y1} ${x2 - 40},${y2} ${x2},${y2}`}
                fill="none"
                stroke={lit ? 'var(--accent)' : 'var(--border-strong)'}
                strokeWidth={lit ? 2 : 1}
                opacity={highlighted && !lit ? 0.25 : 0.9}
              />
            );
          })}
          {layout.positioned.map((n) => {
            const faded = (highlighted && !highlighted.has(n.id)) || (!highlighted && n.dim);
            return (
              <g
                key={n.id}
                transform={`translate(${n.x},${n.y})`}
                opacity={faded ? 0.4 : 1}
                onMouseEnter={() => setFocus(n.id)}
                onMouseLeave={() => setFocus(null)}
                onClick={() => n.assetId && onOpen(n.assetId)}
                style={{ cursor: n.assetId ? 'pointer' : 'default' }}
              >
                <title>{`${n.label}${n.sub ? `\n${n.sub}` : ''}`}</title>
                <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx={6} fill="var(--panel)" stroke={n.color} strokeWidth={1.3} />
                <rect width={4} height={NODE_HEIGHT} rx={2} fill={n.color} />
                <text x={10} y={16}>
                  {n.label.length > 27 ? `${n.label.slice(0, 26)}…` : n.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </Panel>
  );
}
