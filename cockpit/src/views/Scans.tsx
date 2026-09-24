import { useEffect, useState } from 'react';
import { api } from '../api';
import type { ScanMeta, ScanProgress } from '../types';
import { when } from '../format';
import { Icon, Panel } from '../ui';

export function Scans({
  scans,
  canScan,
  onError,
  onStarted,
  onOpen,
  onRefresh,
}: {
  scans: ScanMeta[];
  /** Viewers see history but cannot start scans. */
  canScan: boolean;
  onError: (e: unknown) => void;
  onStarted: (meta: ScanMeta) => void;
  onOpen: (id: string) => void;
  onRefresh: () => Promise<void>;
}) {
  const [launching, setLaunching] = useState(false);
  return (
    <div className="grid">
      <Panel
        title="Scans"
        hint="each scan reads only inside a root the server operator configured"
        actions={
          <span style={{ display: 'flex', gap: 8 }}>
            <button className="btn" onClick={() => void onRefresh()}>
              <Icon name="refresh" /> Refresh
            </button>
            {canScan && (
              <button className="btn primary" onClick={() => setLaunching(true)}>
                <Icon name="plus" /> New scan
              </button>
            )}
          </span>
        }
      >
        {scans.length === 0 ? (
          <div className="empty">No scans yet.</div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Subject</th>
                  <th>Target</th>
                  <th>Requested</th>
                  <th className="num">Assets</th>
                  <th className="num">Urgent</th>
                  <th className="num">Critical</th>
                  <th className="num">Duration</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} onClick={() => s.status === 'done' && onOpen(s.id)} style={{ cursor: s.status === 'done' ? 'pointer' : 'default' }}>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <span className={`status-dot status-${s.status}`} />
                        {s.status}
                      </span>
                      {s.error && <div className="faint">{s.error}</div>}
                      {s.progress && <ProgressBar progress={s.progress} />}
                    </td>
                    <td style={{ fontWeight: 600 }}>{s.subject}</td>
                    <td className="mono">
                      {s.root}:{s.path || '/'}
                    </td>
                    <td>
                      {when(s.requested)}
                      {s.requestedBy && <div className="faint">by {s.requestedBy}</div>}
                    </td>
                    <td className="num">{s.summary?.assets ?? '–'}</td>
                    <td className="num">{s.summary?.moscaUrgent ?? '–'}</td>
                    <td className="num">{s.summary?.critical ?? '–'}</td>
                    <td className="num">{s.durationMs !== undefined ? `${(s.durationMs / 1000).toFixed(1)} s` : '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {launching && (
        <Launcher
          onClose={() => setLaunching(false)}
          onError={onError}
          onStarted={(meta) => {
            setLaunching(false);
            onStarted(meta);
          }}
        />
      )}
    </div>
  );
}

function Launcher({ onClose, onError, onStarted }: { onClose: () => void; onError: (e: unknown) => void; onStarted: (meta: ScanMeta) => void }) {
  const [roots, setRoots] = useState<string[]>([]);
  const [root, setRoot] = useState('');
  const [path, setPath] = useState('');
  const [listing, setListing] = useState<{ directories: string[]; files: number; truncated: boolean } | null>(null);
  const [subject, setSubject] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .roots()
      .then((list) => {
        setRoots(list.map((r) => r.name));
        setRoot((current) => current || list[0]?.name || '');
      })
      .catch(onError);
  }, [onError]);

  useEffect(() => {
    if (!root) return;
    setListing(null);
    api.entries(root, path).then(setListing).catch(onError);
  }, [root, path, onError]);

  const segments = path ? path.split('/') : [];

  return (
    <div className="modal" role="dialog" aria-modal="true" aria-labelledby="launch-title">
      <form
        className="panel"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            onStarted(await api.startScan({ root, path, subject: subject.trim() || undefined }));
          } catch (error) {
            onError(error);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="panel-head">
          <h2 id="launch-title">New scan</h2>
          <span className="hint">read-only · nothing is executed · no network</span>
        </div>
        <div className="panel-body grid" style={{ gap: 10 }}>
          <label className="grid" style={{ gap: 4 }}>
            <span className="muted">Root</span>
            <select
              className="select"
              value={root}
              onChange={(e) => {
                setRoot(e.target.value);
                setPath('');
              }}
            >
              {roots.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <div>
            <span className="muted">Target</span>
            <div className="mono" style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
              <button type="button" className="btn" onClick={() => setPath('')}>
                {root || 'root'}
              </button>
              {segments.map((segment, i) => (
                <button type="button" className="btn" key={i} onClick={() => setPath(segments.slice(0, i + 1).join('/'))}>
                  {segment}
                </button>
              ))}
            </div>
            <div className="dir-list">
              {listing?.directories.map((d) => (
                <button type="button" key={d} onClick={() => setPath(path ? `${path}/${d}` : d)}>
                  {d}/
                </button>
              ))}
              {listing && listing.directories.length === 0 && <div className="faint" style={{ padding: 10 }}>No sub-directories.</div>}
            </div>
            <span className="faint">
              {listing ? `${listing.files} files here${listing.truncated ? ' · listing truncated' : ''}` : 'Loading…'}
            </span>
          </div>
          <label className="grid" style={{ gap: 4 }}>
            <span className="muted">Subject name (optional)</span>
            <input className="input" value={subject} maxLength={128} onChange={(e) => setSubject(e.target.value)} placeholder={segments.at(-1) ?? root} />
          </label>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button className="btn primary" type="submit" disabled={!root || busy}>
              Scan {path ? `${root}/${path}` : root}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

function ProgressBar({ progress }: { progress: ScanProgress }) {
  const total = progress.filesTotal + progress.archivesTotal;
  const done = progress.filesDone + progress.archivesDone;
  const collecting = progress.phase === 'collecting' && total > 0;
  const share = collecting ? done / total : progress.phase === 'queued' || progress.phase === 'listing' ? 0 : 1;
  const label =
    progress.phase === 'collecting'
      ? `${done.toLocaleString()} of ${total.toLocaleString()} files`
      : progress.phase === 'queued'
        ? 'waiting for a free slot'
        : progress.phase;
  return (
    <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(share * 100)} aria-label="Scan progress">
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${Math.round(share * 100)}%` }} />
      </div>
      <span className="faint">{label}</span>
    </div>
  );
}
