import type { AuditPage, Comparison, Graph, Health, Principal, Report, ScanMeta } from './types';

const TOKEN_KEY = 'lattice.token';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function token(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(value: string | null): void {
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage unavailable (private mode): the token lives only for this page
  }
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const bearer = token();
  if (bearer) headers.set('Authorization', `Bearer ${bearer}`);
  if (init.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers, credentials: 'omit' });
  if (!response.ok) {
    let message = response.statusText;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // not JSON
    }
    throw new ApiError(response.status, message);
  }
  return response;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await request(path, init)).json() as Promise<T>;
}

const scanPath = (id: string) => `/api/scans/${encodeURIComponent(id)}`;

export const api = {
  health: () => json<Health>('/api/health'),
  whoami: () => json<Principal>('/api/whoami'),
  audit: (limit: number) => json<AuditPage>(`/api/audit?limit=${limit}`),
  roots: () => json<{ name: string }[]>('/api/roots'),
  entries: (root: string, path: string) =>
    json<{ path: string; directories: string[]; files: number; truncated: boolean }>(
      `/api/roots/${encodeURIComponent(root)}/entries?path=${encodeURIComponent(path)}`,
    ),
  scans: () => json<ScanMeta[]>('/api/scans'),
  scan: (id: string) => json<ScanMeta>(scanPath(id)),
  startScan: (body: { root: string; path: string; subject?: string; subjectVersion?: string }) =>
    json<ScanMeta>('/api/scans', { method: 'POST', body: JSON.stringify(body) }),
  report: (id: string) => json<Report>(`${scanPath(id)}/report`),
  graph: (id: string) => json<Graph>(`${scanPath(id)}/graph`),
  compare: (baseline: string, current: string, failOn: string) =>
    json<Comparison>(
      `/api/compare?baseline=${encodeURIComponent(baseline)}&current=${encodeURIComponent(current)}&failOn=${encodeURIComponent(failOn)}`,
    ),
  downloadCbom: (id: string) => download(`${scanPath(id)}/cbom?download=1`, `lattice-${id}.cdx.json`),
  /** The executive report as PDF, rendered by the server from the stored report. */
  downloadPdf: (id: string) => download(`${scanPath(id)}/report.pdf`, `lattice-${id}.pdf`),
};

/** Downloads through fetch so the bearer token applies, then saves via an object URL. */
async function download(path: string, filename: string): Promise<void> {
  const response = await request(path);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Follows a scan's server-sent events until it ends. Read with fetch rather than EventSource,
 * so the bearer token is sent as on every other call. Resolves with the final record.
 */
export async function followScan(id: string, onProgress: (meta: ScanMeta) => void, signal: AbortSignal): Promise<ScanMeta | null> {
  const response = await request(`${scanPath(id)}/events`, { signal });
  const reader = response.body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let buffered = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return null;
    buffered += decoder.decode(value, { stream: true });
    let end: number;
    while ((end = buffered.indexOf('\n\n')) >= 0) {
      const block = buffered.slice(0, end);
      buffered = buffered.slice(end + 2);
      const name = block.match(/^event: (.*)$/m)?.[1];
      const data = block.match(/^data: (.*)$/m)?.[1];
      if (!data) continue;
      const meta = JSON.parse(data) as ScanMeta;
      if (name === 'end') return meta;
      onProgress(meta);
    }
  }
}
