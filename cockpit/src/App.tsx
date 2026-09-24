import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, api, setToken } from './api';
import type { AssetReport, Graph, Health, Principal, Report, ScanMeta } from './types';
import { Icon, Logo } from './ui';
import { Overview } from './views/Overview';
import { Inventory } from './views/Inventory';
import { AssetDrawer } from './views/AssetDrawer';
import { GraphView } from './views/GraphView';
import { Roadmap } from './views/Roadmap';
import { Compare } from './views/Compare';
import { Scans } from './views/Scans';
import { Audit } from './views/Audit';
import { when } from './format';

type View = 'overview' | 'inventory' | 'graph' | 'roadmap' | 'compare' | 'scans' | 'audit';

const VIEWS: { id: View; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'graph', label: 'Crypto graph' },
  { id: 'roadmap', label: 'Roadmap' },
  { id: 'compare', label: 'Compare' },
  { id: 'scans', label: 'Scans' },
  { id: 'audit', label: 'Audit log' },
];

function readHash(): { view: View; scan: string | null } {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const view = params.get('view') as View | null;
  return { view: view && VIEWS.some((v) => v.id === view) ? view : 'overview', scan: params.get('scan') };
}

export function App() {
  const initial = readHash();
  const [view, setView] = useState<View>(initial.view);
  const [scanId, setScanId] = useState<string | null>(initial.scan);
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [needsToken, setNeedsToken] = useState(false);
  const [me, setMe] = useState<Principal | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light' | null>(null);

  const handle = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) setNeedsToken(true);
    else setError(e instanceof Error ? e.message : String(e));
  }, []);

  const refreshScans = useCallback(async () => {
    try {
      setMe(await api.whoami());
      const list = await api.scans();
      setScans(list);
      setScanId((current) => current ?? list.find((s) => s.status === 'done')?.id ?? null);
    } catch (e) {
      handle(e);
    }
  }, [handle]);

  useEffect(() => {
    api.health().then(setHealth).catch(handle);
    void refreshScans();
  }, [refreshScans, handle]);

  // poll while anything is queued or running
  useEffect(() => {
    if (!scans.some((s) => s.status === 'queued' || s.status === 'running')) return;
    const timer = setInterval(() => void refreshScans(), 1500);
    return () => clearInterval(timer);
  }, [scans, refreshScans]);

  const current = scans.find((s) => s.id === scanId) ?? null;
  const ready = current?.status === 'done';

  useEffect(() => {
    setReport(null);
    setGraph(null);
    setSelected(null);
    if (!scanId || !ready) return;
    let cancelled = false;
    Promise.all([api.report(scanId), api.graph(scanId)])
      .then(([r, g]) => {
        if (!cancelled) {
          setReport(r);
          setGraph(g);
        }
      })
      .catch(handle);
    return () => {
      cancelled = true;
    };
  }, [scanId, ready, handle]);

  useEffect(() => {
    const params = new URLSearchParams();
    params.set('view', view);
    if (scanId) params.set('scan', scanId);
    window.history.replaceState(null, '', `#${params.toString()}`);
  }, [view, scanId]);

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme;
  }, [theme]);

  const selectedAsset: AssetReport | null = useMemo(
    () => report?.assets.find((a) => a.asset.id === selected) ?? null,
    [report, selected],
  );

  const open = (assetId: string) => setSelected(assetId);
  const title = VIEWS.find((v) => v.id === view)?.label ?? '';

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Views">
        <div className="brand">
          <Logo />
          <div>
            <strong>LATTICE</strong>
            <small>Quantum-risk cockpit</small>
          </div>
        </div>
        {VIEWS.filter((v) => v.id !== 'audit' || me?.role === 'admin').map((v) => (
          <button key={v.id} className={`nav-item ${view === v.id ? 'active' : ''}`} onClick={() => setView(v.id)} aria-current={view === v.id ? 'page' : undefined}>
            <Icon name={v.id} />
            {v.label}
          </button>
        ))}
        <div className="sidebar-footer">
          {health ? (
            <>
              <span>engine {health.version}</span>
              <span title={health.knowledgeSigner ? `signed knowledge bundle, key ${health.knowledgeSigner}` : 'knowledge compiled into this release'}>
                knowledge {health.knowledgeVersion} #{health.knowledgeSequence}
                {health.knowledgeSigner ? ' · bundle' : ''}
              </span>
              <span>
                Q-day window {health.qDay[0]}–{health.qDay[1]}
              </span>
              <span>offline · read-only</span>
              {me && health.authentication && (
                <span>
                  signed in as <strong>{me.name}</strong> ({me.role}){' '}
                  <button
                    className="link"
                    onClick={() => {
                      setToken(null);
                      setMe(null);
                      setScans([]);
                      setNeedsToken(true);
                    }}
                  >
                    sign out
                  </button>
                </span>
              )}
              <span
                title={health.sandbox ? `filesystem: ${health.sandbox.filesystem.state}; system calls: ${health.sandbox.syscalls.state}` : 'the server was started without confinement'}
                style={{ color: health.sandbox && health.sandbox.filesystem.state === 'enforced' && health.sandbox.syscalls.state === 'enforced' ? 'var(--safe)' : 'var(--high)' }}
              >
                {health.sandbox && health.sandbox.filesystem.state === 'enforced' && health.sandbox.syscalls.state === 'enforced'
                  ? 'sandboxed: Landlock + seccomp'
                  : 'sandbox: not fully enforced'}
              </span>
            </>
          ) : (
            <span>connecting…</span>
          )}
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <h1>{title}</h1>
          {current && view !== 'scans' && view !== 'compare' && view !== 'audit' && (
            <span className="faint">
              {current.subject} · {when(current.requested)}
            </span>
          )}
          <span className="spacer" />
          {view !== 'scans' && view !== 'compare' && view !== 'audit' && (
            <select className="select" value={scanId ?? ''} onChange={(e) => setScanId(e.target.value || null)} aria-label="Scan">
              {scans.length === 0 && <option value="">No scans yet</option>}
              {scans.map((s) => (
                <option key={s.id} value={s.id} disabled={s.status !== 'done'}>
                  {s.subject} · {when(s.requested)} {s.status !== 'done' ? `(${s.status})` : ''}
                </option>
              ))}
            </select>
          )}
          {ready && scanId && (
            <>
              <button className="btn" onClick={() => api.downloadCbom(scanId).catch(handle)} title="Download the CycloneDX 1.6 CBOM">
                <Icon name="download" /> CBOM
              </button>
              <button className="btn" onClick={() => api.downloadPdf(scanId).catch(handle)} title="Download the executive report (PDF)">
                <Icon name="download" /> PDF
              </button>
            </>
          )}
          <button
            className="btn"
            aria-label="Toggle theme"
            onClick={() => setTheme((t) => (t === 'light' || (!t && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'dark' : 'light'))}
          >
            <Icon name="sun" />
          </button>
        </header>

        <main className="content">
          {error && (
            <div className="error-box" style={{ marginBottom: 16 }} role="alert">
              {error}{' '}
              <button className="btn" style={{ marginLeft: 8 }} onClick={() => setError(null)}>
                Dismiss
              </button>
            </div>
          )}
          {view === 'scans' || view === 'compare' || view === 'audit' ? null : !scanId ? (
            <div className="panel empty">
              <p>No completed scan yet.</p>
              {me?.role !== 'viewer' && (
                <button className="btn primary" onClick={() => setView('scans')}>
                  <Icon name="plus" /> Start a scan
                </button>
              )}
            </div>
          ) : !report ? (
            <div className="panel empty">{current?.status === 'failed' ? `This scan failed: ${current.error ?? ''}` : 'Loading report…'}</div>
          ) : null}

          {report && view === 'overview' && <Overview report={report} onOpen={open} />}
          {report && view === 'inventory' && <Inventory report={report} selected={selected} onOpen={open} />}
          {report && graph && view === 'graph' && <GraphView report={report} graph={graph} onOpen={open} />}
          {report && view === 'roadmap' && <Roadmap report={report} onOpen={open} />}
          {view === 'compare' && <Compare scans={scans} onError={handle} />}
          {view === 'audit' && me?.role === 'admin' && <Audit onError={handle} />}
          {view === 'scans' && (
            <Scans
              scans={scans}
              canScan={me?.role !== 'viewer'}
              onError={handle}
              onStarted={(meta) => {
                setScans((list) => [meta, ...list]);
                setScanId(meta.id);
              }}
              onOpen={(id) => {
                setScanId(id);
                setView('overview');
              }}
              onRefresh={refreshScans}
            />
          )}
        </main>
      </div>

      {selectedAsset && report && <AssetDrawer item={selectedAsset} report={report} onClose={() => setSelected(null)} onOpen={open} />}
      {needsToken && (
        <TokenPrompt
          onSubmit={(value) => {
            setToken(value);
            setNeedsToken(false);
            setError(null);
            void refreshScans();
          }}
        />
      )}
    </div>
  );
}

function TokenPrompt({ onSubmit }: { onSubmit: (token: string) => void }) {
  const [value, setValue] = useState('');
  return (
    <div className="modal" role="dialog" aria-modal="true" aria-labelledby="token-title">
      <form
        className="panel"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) onSubmit(value.trim());
        }}
      >
        <div className="panel-head">
          <h2 id="token-title">API token required</h2>
        </div>
        <div className="panel-body grid">
          <p className="muted" style={{ margin: 0 }}>
            This LATTICE server requires a bearer token. It is kept for this browser tab only.
          </p>
          <input className="input" type="password" autoFocus value={value} onChange={(e) => setValue(e.target.value)} placeholder="Token" autoComplete="off" />
          <div>
            <button className="btn primary" type="submit">
              Continue
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
