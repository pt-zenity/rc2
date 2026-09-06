import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool';
import { requireAuth, requireRole } from '../middleware/auth';
import { audit } from '../middleware/audit';
import { scanQueue } from '../../worker/queue';
import { config } from '../../config';

export const scansRouter = Router();
scansRouter.use(requireAuth);

const ALL_TOOLS = [
  'subfinder',
  'dnsx',
  'httpx',
  'naabu',
  'katana',
  'gau',
  'ffuf',
  'nuclei',
] as const;

const createSchema = z.object({
  target_id: z.number().int().positive(),
  tools: z.array(z.enum(ALL_TOOLS)).optional(),
  nuclei_high_risk: z.boolean().optional().default(false),
});

scansRouter.post('/', requireRole('admin', 'analyst'), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const { target_id, tools, nuclei_high_risk } = parsed.data;

  const targetRes = await pool.query('SELECT * FROM targets WHERE id = $1', [target_id]);
  if (targetRes.rows.length === 0) {
    return res.status(404).json({ error: 'Target not found' });
  }
  const target = targetRes.rows[0];
  if (!target.authorized) {
    return res.status(403).json({
      error: 'Target is not authorized for scanning. An admin/analyst must authorize it first.',
    });
  }

  if (nuclei_high_risk && !config.enableHighRiskTemplates) {
    return res.status(403).json({
      error: 'High-risk templates are disabled by server configuration (ENABLE_HIGH_RISK_TEMPLATES=false).',
    });
  }

  const scanConfig = {
    tools: tools && tools.length > 0 ? tools : ALL_TOOLS,
    nuclei_high_risk: nuclei_high_risk && config.enableHighRiskTemplates,
  };

  const { rows } = await pool.query(
    `INSERT INTO scans (target_id, status, config, created_by) VALUES ($1, 'queued', $2, $3) RETURNING *`,
    [target_id, JSON.stringify(scanConfig), req.user!.sub]
  );
  const scan = rows[0];
  await scanQueue.add('run-scan', { scanId: scan.id }, {
    attempts: 1,
    removeOnComplete: 500,
    removeOnFail: 500,
  });
  await audit(req, 'scan.create', 'scan', scan.id, { target_id });
  return res.status(201).json(scan);
});

scansRouter.get('/', async (req, res) => {
  const page = Math.max(parseInt(String(req.query.page ?? '1'), 10), 1);
  const pageSize = Math.min(
    Math.max(parseInt(String(req.query.pageSize ?? '25'), 10), 1),
    200
  );
  const status = req.query.status ? String(req.query.status) : undefined;
  const targetId = req.query.target_id ? String(req.query.target_id) : undefined;
  const params: unknown[] = [];
  const clauses: string[] = [];
  if (status) {
    params.push(status);
    clauses.push(`status = $${params.length}`);
  }
  if (targetId) {
    params.push(targetId);
    clauses.push(`target_id = $${params.length}`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const countRes = await pool.query(`SELECT COUNT(*)::int AS c FROM scans ${where}`, params);
  params.push(pageSize, (page - 1) * pageSize);
  const { rows } = await pool.query(
    `SELECT * FROM scans ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  return res.json({ data: rows, pagination: { page, pageSize, total: countRes.rows[0].c } });
});

scansRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1', [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  return res.json(rows[0]);
});

scansRouter.get('/:id/jobs', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM scan_jobs WHERE scan_id = $1 ORDER BY id ASC',
    [req.params.id]
  );
  return res.json({ data: rows });
});

scansRouter.get('/:id/logs', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM scan_logs WHERE scan_id = $1 ORDER BY id ASC LIMIT 2000',
    [req.params.id]
  );
  return res.json({ data: rows });
});

scansRouter.get('/:id/evidence', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, scan_id, scan_job_id, tool_name, kind, byte_size, created_at FROM evidence WHERE scan_id = $1 ORDER BY id ASC',
    [req.params.id]
  );
  return res.json({ data: rows });
});

scansRouter.get('/:id/evidence/:evidenceId/raw', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM evidence WHERE id = $1 AND scan_id = $2', [
    req.params.evidenceId,
    req.params.id,
  ]);
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.type('text/plain');
  return res.sendFile(rows[0].file_path, { root: '/' }, (err) => {
    if (err) res.status(404).json({ error: 'Evidence file missing on disk' });
  });
});

// Cancellation: marks the scan cancelled; the worker checks this flag between
// pipeline steps and stops launching further scanner processes. Already
// in-flight child processes are killed by the worker's cancellation watcher.
scansRouter.post('/:id/cancel', requireRole('admin', 'analyst'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE scans SET status = 'cancelled', finished_at = now()
     WHERE id = $1 AND status IN ('queued','running') RETURNING *`,
    [req.params.id]
  );
  if (rows.length === 0) {
    return res.status(409).json({ error: 'Scan is not cancellable in its current state' });
  }
  await audit(req, 'scan.cancel', 'scan', req.params.id);
  return res.json(rows[0]);
});
