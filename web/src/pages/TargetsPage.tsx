import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, type Paginated } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface Target {
  id: number;
  value: string;
  kind: string;
  authorized: boolean;
  authorization_note: string | null;
  created_at: string;
}

export function TargetsPage() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analyst';
  const [targets, setTargets] = useState<Target[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  function load() {
    apiFetch<Paginated<Target>>(`/api/targets?page=${page}&pageSize=25`).then((res) => {
      setTargets(res.data);
      setTotal(res.pagination.total);
    });
  }

  useEffect(load, [page]);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await apiFetch('/api/targets', {
        method: 'POST',
        body: JSON.stringify({ value, authorization_note: note || undefined }),
      });
      setValue('');
      setNote('');
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create target');
    } finally {
      setBusy(false);
    }
  }

  async function toggleAuthorize(t: Target) {
    setError(null);
    try {
      await apiFetch(`/api/targets/${t.id}/authorize`, {
        method: 'PATCH',
        body: JSON.stringify({ authorized: !t.authorized }),
      });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update authorization');
    }
  }

  return (
    <div className="page">
      <h1>Targets</h1>
      <p className="muted">
        Targets must be explicitly authorized before any scan can be launched against them. Only
        publicly-routable, non-loopback/private hosts are accepted by default (SSRF protection).
      </p>
      {canManage && (
        <form className="inline-form" onSubmit={onCreate}>
          <input
            placeholder="domain.example.com or 203.0.113.10"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            required
          />
          <input
            placeholder="Authorization note (optional)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <button type="submit" disabled={busy}>
            Add target
          </button>
        </form>
      )}
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Value</th>
            <th>Kind</th>
            <th>Authorized</th>
            <th>Added</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {targets.length === 0 && (
            <tr>
              <td colSpan={5} className="empty">
                No targets yet.
              </td>
            </tr>
          )}
          {targets.map((t) => (
            <tr key={t.id}>
              <td>{t.value}</td>
              <td>{t.kind}</td>
              <td>
                <span className={t.authorized ? 'badge badge-ok' : 'badge badge-warn'}>
                  {t.authorized ? 'Authorized' : 'Not authorized'}
                </span>
              </td>
              <td>{new Date(t.created_at).toLocaleString()}</td>
              <td>
                {canManage && (
                  <button onClick={() => toggleAuthorize(t)}>
                    {t.authorized ? 'Revoke' : 'Authorize'}
                  </button>
                )}
                <button onClick={() => navigate(`/scans?target_id=${t.id}`)}>View scans</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="pagination">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
          Prev
        </button>
        <span>Page {page}, {total} total</span>
        <button disabled={page * 25 >= total} onClick={() => setPage((p) => p + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
