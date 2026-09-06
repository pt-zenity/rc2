import { useEffect, useState } from 'react';
import { apiFetch, type Paginated } from '../api/client';

interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => React.ReactNode;
}

export function ResultsTable<T extends Record<string, unknown>>({
  resource,
  scanId,
  columns,
  extraParams,
}: {
  resource: string;
  scanId: number;
  columns: Column<T>[];
  extraParams?: Record<string, string>;
}) {
  const [rows, setRows] = useState<T[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pageSize = 25;

  useEffect(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({
      scan_id: String(scanId),
      page: String(page),
      pageSize: String(pageSize),
      ...(search ? { search } : {}),
      ...extraParams,
    });
    apiFetch<Paginated<T>>(`/api/results/${resource}?${params.toString()}`)
      .then((res) => {
        setRows(res.data);
        setTotal(res.pagination.total);
      })
      .catch((err) => setError(String(err.message || err)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resource, scanId, page, search, JSON.stringify(extraParams)]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  async function doExport(format: 'csv' | 'json') {
    const params = new URLSearchParams({ scan_id: String(scanId), format, ...extraParams });
    const token = localStorage.getItem('recon_token');
    const res = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000'}/api/results/${resource}?${params.toString()}`,
      { headers: token ? { Authorization: ['Bearer', token].join(' ') } : {} }
    );
    if (!res.ok) {
      setError(`Export failed: HTTP ${res.status}`);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${resource}-scan-${scanId}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="results-table">
      <div className="table-toolbar">
        <input
          placeholder="Search..."
          value={search}
          onChange={(e) => {
            setPage(1);
            setSearch(e.target.value);
          }}
        />
        <span className="spacer" />
        <button className="btn-secondary" onClick={() => doExport('csv')}>
          Export CSV
        </button>
        <button className="btn-secondary" onClick={() => doExport('json')}>
          Export JSON
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {loading ? (
        <p>Loading…</p>
      ) : (
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key}>{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="empty">
                  No results found for this scan.
                </td>
              </tr>
            )}
            {rows.map((row, i) => (
              <tr key={i}>
                {columns.map((c) => (
                  <td key={c.key}>{c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '')}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="pagination">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
          Prev
        </button>
        <span>
          Page {page} / {totalPages} ({total} total)
        </span>
        <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
