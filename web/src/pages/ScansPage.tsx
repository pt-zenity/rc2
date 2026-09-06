import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiFetch, type Paginated } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface Target {
  id: number;
  value: string;
  authorized: boolean;
}

interface Scan {
  id: number;
  target_id: number;
  status: string;
  config: { tools: string[]; nuclei_high_risk: boolean };
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

const ALL_TOOLS = ['subfinder', 'dnsx', 'httpx', 'naabu', 'katana', 'gau', 'ffuf', 'nuclei'];

const STATUS_CLASS: Record<string, string> = {
  queued: 'badge badge-neutral',
  running: 'badge badge-info',
  completed: 'badge badge-ok',
  partial: 'badge badge-warn',
  failed: 'badge badge-error',
  cancelled: 'badge badge-neutral',
};

export function ScansPage() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analyst';
  const [params] = useSearchParams();
  const targetIdFilter = params.get('target_id') ?? '';
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState(targetIdFilter);
  const [tools, setTools] = useState<string[]>(ALL_TOOLS);
  const [nucleiHighRisk, setNucleiHighRisk] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  function load() {
    const qs = targetIdFilter ? `&target_id=${targetIdFilter}` : '';
    apiFetch<Paginated<Scan>>(`/api/scans?page=1&pageSize=50${qs}`).then((res) => setScans(res.data));
  }

  useEffect(load, [targetIdFilter]);
  useEffect(() => {
    apiFetch<Paginated<Target>>('/api/targets?page=1&pageSize=200').then((res) =>
      setTargets(res.data.filter((t) => t.authorized))
    );
  }, []);

  function toggleTool(tool: string) {
    setTools((cur) => (cur.includes(tool) ? cur.filter((t) => t !== tool) : [...cur, tool]));
  }

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const scan = await apiFetch<Scan>('/api/scans', {
        method: 'POST',
        body: JSON.stringify({
          target_id: Number(targetId),
          tools,
          nuclei_high_risk: nucleiHighRisk,
        }),
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <h1>Scans</h1>
      {canManage && (
        <form className="scan-form" onSubmit={onCreate}>
          <label>
            Target
            <select value={targetId} onChange={(e) => setTargetId(e.target.value)} required>
              <option value="">Select authorized target…</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.value}
                </option>
              ))}
            </select>
          </label>
          <fieldset>
            <legend>Tools</legend>
            {ALL_TOOLS.map((tool) => (
              <label key={tool} className="checkbox-label">
                <input
                  type="checkbox"
                  checked={tools.includes(tool)}
                  onChange={() => toggleTool(tool)}
                />
                {tool}
              </label>
            ))}
          </fieldset>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={nucleiHighRisk}
              onChange={(e) => setNucleiHighRisk(e.target.checked)}
            />
            Enable high-risk nuclei templates (must also be allowed by server config)
          </label>
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={busy || !targetId}>
            Launch scan
          </button>
        </form>
      )}
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Tools</th>
            <th>Created</th>
            <th>Finished</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {scans.length === 0 && (
            <tr>
              <td colSpan={6} className="empty">
                No scans yet.
              </td>
            </tr>
          )}
          {scans.map((s) => (
            <tr key={s.id}>
              <td>#{s.id}</td>
              <td>
                <span className={STATUS_CLASS[s.status] ?? 'badge'}>{s.status}</span>
              </td>
              <td>{s.config?.tools?.join(', ')}</td>
              <td>{new Date(s.created_at).toLocaleString()}</td>
              <td>{s.finished_at ? new Date(s.finished_at).toLocaleString() : '—'}</td>
              <td>
                <button onClick={() => navigate(`/scans/${s.id}`)}>View</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
