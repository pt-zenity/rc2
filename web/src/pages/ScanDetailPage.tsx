import { useEffect, useState, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiFetch } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ResultsTable } from '../components/ResultsTable';

interface Scan {
  id: number;
  target_id: number;
  status: string;
  config: { tools: string[]; nuclei_high_risk: boolean };
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

interface ScanJob {
  id: number;
  tool_name: string;
  status: string;
  attempt: number;
  exit_code: number | null;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
}

interface ScanLog {
  id: number;
  tool_name: string | null;
  level: string;
  message: string;
  created_at: string;
}

interface EvidenceItem {
  id: number;
  tool_name: string;
  kind: string;
  byte_size: number;
  created_at: string;
}

type Tab =
  | 'overview'
  | 'subdomains'
  | 'dns'
  | 'ips'
  | 'ports'
  | 'hosts'
  | 'technologies'
  | 'urls'
  | 'findings'
  | 'logs'
  | 'evidence';

const TABS: { key: Tab; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'subdomains', label: 'Subdomains' },
  { key: 'dns', label: 'DNS' },
  { key: 'ips', label: 'IP Addresses' },
  { key: 'ports', label: 'Ports/Services' },
  { key: 'hosts', label: 'Live Hosts' },
  { key: 'technologies', label: 'Technologies' },
  { key: 'urls', label: 'URLs/Endpoints' },
  { key: 'findings', label: 'Findings' },
  { key: 'logs', label: 'Scan Logs' },
  { key: 'evidence', label: 'Raw Evidence' },
];

export function ScanDetailPage() {
  const { id } = useParams();
  const scanId = Number(id);
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analyst';
  const [scan, setScan] = useState<Scan | null>(null);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [tab, setTab] = useState<Tab>('overview');
  const navigate = useNavigate();

  const load = useCallback(() => {
    apiFetch<Scan>(`/api/scans/${scanId}`).then(setScan);
    apiFetch<{ data: ScanJob[] }>(`/api/scans/${scanId}/jobs`).then((r) => setJobs(r.data));
  }, [scanId]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 4000);
    return () => clearInterval(interval);
  }, [load]);

  useEffect(() => {
    if (tab === 'logs') {
      apiFetch<{ data: ScanLog[] }>(`/api/scans/${scanId}/logs`).then((r) => setLogs(r.data));
    } else if (tab === 'evidence') {
      apiFetch<{ data: EvidenceItem[] }>(`/api/scans/${scanId}/evidence`).then((r) =>
        setEvidence(r.data)
      );
    }
  }, [tab, scanId]);

  async function onCancel() {
    await apiFetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
    load();
  }

  function downloadEvidence(evId: number) {
    const token = localStorage.getItem('recon_token');
    fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000'}/api/scans/${scanId}/evidence/${evId}/raw`,
      { headers: token ? { Authorization: ['Bearer', token].join(' ') } : {} }
    )
      .then((r) => r.blob())
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `evidence-${evId}.txt`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      });
  }

  if (!scan) return <p>Loading…</p>;

  return (
    <div className="page">
      <button className="link-button" onClick={() => navigate('/scans')}>
        ← Back to scans
      </button>
      <h1>
        Scan #{scan.id} <span className="badge">{scan.status}</span>
      </h1>
      <p className="muted">
        Tools: {scan.config?.tools?.join(', ')} · Started:{' '}
        {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'} · Finished:{' '}
        {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '—'}
      </p>
      {canManage && (scan.status === 'queued' || scan.status === 'running') && (
        <button onClick={onCancel}>Cancel scan</button>
      )}

      <div className="tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={tab === t.key ? 'tab active' : 'tab'}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Status</th>
              <th>Attempt</th>
              <th>Exit code</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id}>
                <td>{j.tool_name}</td>
                <td>
                  <span className={`badge badge-${j.status === 'completed' ? 'ok' : j.status === 'failed' ? 'error' : 'neutral'}`}>
                    {j.status}
                  </span>
                </td>
                <td>{j.attempt}</td>
                <td>{j.exit_code ?? '—'}</td>
                <td>{j.started_at ? new Date(j.started_at).toLocaleTimeString() : '—'}</td>
                <td>{j.finished_at ? new Date(j.finished_at).toLocaleTimeString() : '—'}</td>
                <td>{j.error_message ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'subdomains' && (
        <ResultsTable
          resource="subdomains"
          scanId={scanId}
          columns={[
            { key: 'hostname', label: 'Hostname' },
            { key: 'source', label: 'Source' },
            { key: 'created_at', label: 'Discovered' },
          ]}
        />
      )}
      {tab === 'dns' && (
        <ResultsTable
          resource="dns"
          scanId={scanId}
          columns={[
            { key: 'hostname', label: 'Hostname' },
            { key: 'record_type', label: 'Type' },
            { key: 'value', label: 'Value' },
          ]}
        />
      )}
      {tab === 'ips' && (
        <ResultsTable
          resource="ips"
          scanId={scanId}
          columns={[
            { key: 'ip', label: 'IP' },
            { key: 'hostname', label: 'Hostname' },
          ]}
        />
      )}
      {tab === 'ports' && (
        <ResultsTable
          resource="ports"
          scanId={scanId}
          columns={[
            { key: 'ip', label: 'IP' },
            { key: 'port', label: 'Port' },
            { key: 'protocol', label: 'Protocol' },
          ]}
        />
      )}
      {tab === 'hosts' && (
        <ResultsTable
          resource="hosts"
          scanId={scanId}
          columns={[
            { key: 'url', label: 'URL' },
            { key: 'status_code', label: 'Status' },
            { key: 'title', label: 'Title' },
            { key: 'webserver', label: 'Server' },
          ]}
        />
      )}
      {tab === 'technologies' && (
        <ResultsTable
          resource="technologies"
          scanId={scanId}
          columns={[
            { key: 'name', label: 'Technology' },
            { key: 'version', label: 'Version' },
            { key: 'url', label: 'URL' },
          ]}
        />
      )}
      {tab === 'urls' && (
        <ResultsTable
          resource="urls"
          scanId={scanId}
          columns={[
            { key: 'url', label: 'URL' },
            { key: 'source', label: 'Source' },
            { key: 'status_code', label: 'Status' },
          ]}
        />
      )}
      {tab === 'findings' && (
        <ResultsTable
          resource="findings"
          scanId={scanId}
          columns={[
            { key: 'severity', label: 'Severity', render: (r) => (
              <span className={`badge badge-sev-${String(r.severity)}`}>{String(r.severity)}</span>
            ) },
            { key: 'name', label: 'Finding' },
            { key: 'template_id', label: 'Template' },
            { key: 'matched_url', label: 'Matched URL' },
            { key: 'tool_name', label: 'Tool' },
          ]}
        />
      )}
      {tab === 'logs' && (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Tool</th>
              <th>Level</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 && (
              <tr>
                <td colSpan={4} className="empty">
                  No log entries yet.
                </td>
              </tr>
            )}
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{new Date(l.created_at).toLocaleTimeString()}</td>
                <td>{l.tool_name ?? '-'}</td>
                <td>{l.level}</td>
                <td className="log-message">{l.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === 'evidence' && (
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Kind</th>
              <th>Size</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {evidence.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  No evidence recorded yet.
                </td>
              </tr>
            )}
            {evidence.map((e) => (
              <tr key={e.id}>
                <td>{e.tool_name}</td>
                <td>{e.kind}</td>
                <td>{e.byte_size} bytes</td>
                <td>{new Date(e.created_at).toLocaleString()}</td>
                <td>
                  <button onClick={() => downloadEvidence(e.id)}>Download raw</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
