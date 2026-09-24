import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { AuditPage } from '../types';
import { when } from '../format';
import { Icon, Panel } from '../ui';

export function Audit({ onError }: { onError: (e: unknown) => void }) {
  const [page, setPage] = useState<AuditPage | null>(null);
  const load = useCallback(() => {
    api.audit(500).then(setPage).catch(onError);
  }, [onError]);
  useEffect(load, [load]);

  return (
    <div className="grid">
      <Panel
        title="Audit log"
        hint={page ? `${page.entries} entries recorded · hash-chained, verify with lattice audit verify` : 'loading…'}
        actions={
          <button className="btn" onClick={load}>
            <Icon name="refresh" /> Refresh
          </button>
        }
      >
        {page && (
          <>
            <div className="faint" style={{ fontSize: 12, marginBottom: 10 }}>
              chain head <span className="mono">{page.head}</span>
            </div>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th className="num">#</th>
                    <th>Time</th>
                    <th>Who</th>
                    <th>Request</th>
                    <th className="num">Status</th>
                    <th>From</th>
                  </tr>
                </thead>
                <tbody>
                  {page.recent.map((entry) => (
                    <tr key={entry.seq} style={{ cursor: 'default' }}>
                      <td className="num mono">{entry.seq}</td>
                      <td>{when(entry.time)}</td>
                      <td>
                        {entry.actor === '-' ? <span className="faint">unauthenticated</span> : <strong>{entry.actor}</strong>}
                        {entry.role && <span className="faint"> · {entry.role}</span>}
                      </td>
                      <td className="mono">
                        {entry.method} {entry.path}
                      </td>
                      <td className="num mono" style={{ color: entry.status >= 400 ? 'var(--critical)' : undefined }}>
                        {entry.status}
                      </td>
                      <td className="mono faint">{entry.peer ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
