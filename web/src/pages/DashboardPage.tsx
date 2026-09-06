import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, type Paginated } from '../api/client';

interface Stats {
  subdomains: number;
  ips: number;
  ports: number;
  live_hosts: number;
  urls: number;
  findings_by_severity: Record<string, number>;
  findings_total: number;
}

interface Scan {
  id: number;
  target_id: number;
  status: string;
  created_at: string;
}

export function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    apiFetch<Stats>('/api/results/stats').then(setStats);
    apiFetch<Paginated<Scan>>('/api/scans?page=1&pageSize=10').then((res) => setScans(res.data));
  }, []);

  return (
    <div className="page">
      <h1>Attack Surface Overview</h1>
      <p className="muted">
        Aggregate statistics across all scans you have access to. Select a scan for full
        traceable detail.
      </p>
      {stats && (
        <div className="stat-grid">
          <div className="stat-card">
            <span className="stat-value">{stats.subdomains}</span>
            <span className="stat-label">Subdomains</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{stats.ips}</span>
            <span className="stat-label">IP addresses</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{stats.ports}</span>
            <span className="stat-label">Open ports</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{stats.live_hosts}</span>
            <span className="stat-label">Live hosts</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{stats.urls}</span>
            <span className="stat-label">URLs/endpoints</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{stats.findings_total}</span>
            <span className="stat-label">Findings</span>
          </div>
        </div>
      )}
      {stats && (
        <div className="severity-grid">
          {Object.entries(stats.findings_by_severity).map(([sev, count]) => (
            <div key={sev} className={`severity-pill severity-${sev}`}>
              {sev}: {count}
            </div>
          ))}
        </div>
      )}
      <h2>Recent scans</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {scans.length === 0 && (
            <tr>
              <td colSpan={4} className="empty">
                No scans yet — add a target and launch one.
              </td>
            </tr>
          )}
          {scans.map((s) => (
            <tr key={s.id}>
              <td>#{s.id}</td>
              <td>
                <span className="badge">{s.status}</span>
              </td>
              <td>{new Date(s.created_at).toLocaleString()}</td>
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
