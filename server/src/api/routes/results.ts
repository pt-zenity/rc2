import { Router } from 'express';
import { pool } from '../../db/pool';
import { requireAuth } from '../middleware/auth';
import { sendListResponse } from '../../lib/exportUtils';

export const resultsRouter = Router();
resultsRouter.use(requireAuth);

interface ResourceConfig {
  table: string;
  searchColumn?: string;
  sortColumns: string[];
  defaultSort: string;
}

const RESOURCES: Record<string, ResourceConfig> = {
  subdomains: { table: 'subdomains', searchColumn: 'hostname', sortColumns: ['id', 'hostname', 'created_at'], defaultSort: 'hostname' },
  dns: { table: 'dns_records', searchColumn: 'hostname', sortColumns: ['id', 'hostname', 'record_type', 'created_at'], defaultSort: 'hostname' },
  ips: { table: 'ip_addresses', searchColumn: 'ip', sortColumns: ['id', 'ip', 'hostname', 'created_at'], defaultSort: 'ip' },
  ports: { table: 'ports', searchColumn: 'ip', sortColumns: ['id', 'ip', 'port', 'created_at'], defaultSort: 'port' },
  hosts: { table: 'http_probes', searchColumn: 'url', sortColumns: ['id', 'url', 'status_code', 'created_at'], defaultSort: 'created_at' },
  technologies: { table: 'technologies', searchColumn: 'name', sortColumns: ['id', 'name', 'created_at'], defaultSort: 'name' },
  urls: { table: 'urls', searchColumn: 'url', sortColumns: ['id', 'url', 'status_code', 'created_at'], defaultSort: 'created_at' },
  findings: { table: 'findings', searchColumn: 'name', sortColumns: ['id', 'name', 'severity', 'created_at'], defaultSort: 'created_at' },
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

for (const [key, resource] of Object.entries(RESOURCES)) {
  resultsRouter.get(`/${key}`, async (req, res) => {
    const page = Math.max(parseInt(String(req.query.page ?? '1'), 10), 1);
    const pageSize = Math.min(Math.max(parseInt(String(req.query.pageSize ?? '50'), 10), 1), 500);
    const scanId = req.query.scan_id ? String(req.query.scan_id) : undefined;
    const targetId = req.query.target_id ? String(req.query.target_id) : undefined;
    const search = req.query.search ? String(req.query.search).trim() : undefined;
    const severity = req.query.severity ? String(req.query.severity) : undefined;
    let sort = String(req.query.sort ?? resource.defaultSort);
    if (!resource.sortColumns.includes(sort)) sort = resource.defaultSort;
    const order = String(req.query.order ?? 'asc').toLowerCase() === 'desc' ? 'DESC' : 'ASC';

    const params: unknown[] = [];
    const clauses: string[] = [];
    if (scanId) {
      params.push(scanId);
      clauses.push(`scan_id = $${params.length}`);
    }
    if (targetId && key === 'findings') {
      params.push(targetId);
      clauses.push(`target_id = $${params.length}`);
    }
    if (search && resource.searchColumn) {
      params.push(`%${search}%`);
      clauses.push(`${resource.searchColumn} ILIKE $${params.length}`);
    }
    if (severity && key === 'findings') {
      params.push(severity);
      clauses.push(`severity = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

    const format = req.query.format ? String(req.query.format) : undefined;

    if (format === 'csv' || format === 'json') {
      const { rows } = await pool.query(
        `SELECT * FROM ${resource.table} ${where} ORDER BY ${sort} ${order} LIMIT 10000`,
        params
      );
      return sendListResponse(res, rows, format, `${key}-export`);
    }

    const countRes = await pool.query(`SELECT COUNT(*)::int AS c FROM ${resource.table} ${where}`, params);
    params.push(pageSize, (page - 1) * pageSize);
    const { rows } = await pool.query(
      `SELECT * FROM ${resource.table} ${where} ORDER BY ${sort} ${order} LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    return res.json({ data: rows, pagination: { page, pageSize, total: countRes.rows[0].c } });
  });
}

// Attack-surface / findings statistics for the dashboard summary view.
resultsRouter.get('/stats', async (req, res) => {
  const scanId = req.query.scan_id ? String(req.query.scan_id) : undefined;
  const targetId = req.query.target_id ? String(req.query.target_id) : undefined;
  const params: unknown[] = [];
  const clauses: string[] = [];
  if (scanId) {
    params.push(scanId);
    clauses.push(`scan_id = $${params.length}`);
  }
  if (targetId) {
    params.push(targetId);
    clauses.push(`target_id = $${params.length}`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  const [subdomains, ips, ports, hosts, urls, findingsBySeverity] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS c FROM subdomains ${where}`, params),
    pool.query(`SELECT COUNT(DISTINCT ip)::int AS c FROM ip_addresses ${where}`, params),
    pool.query(`SELECT COUNT(*)::int AS c FROM ports ${where}`, params),
    pool.query(`SELECT COUNT(*)::int AS c FROM http_probes ${where}`, params),
    pool.query(`SELECT COUNT(*)::int AS c FROM urls ${where}`, params),
    pool.query(
      `SELECT severity, COUNT(*)::int AS c FROM findings ${where} GROUP BY severity`,
      params
    ),
  ]);

  const severityCounts: Record<string, number> = Object.fromEntries(
    SEVERITY_ORDER.map((s) => [s, 0])
  );
  for (const row of findingsBySeverity.rows) {
    severityCounts[row.severity] = row.c;
  }

  return res.json({
    subdomains: subdomains.rows[0].c,
    ips: ips.rows[0].c,
    ports: ports.rows[0].c,
    live_hosts: hosts.rows[0].c,
    urls: urls.rows[0].c,
    findings_by_severity: severityCounts,
    findings_total: Object.values(severityCounts).reduce((a, b) => a + b, 0),
  });
});
