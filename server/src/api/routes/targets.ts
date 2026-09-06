import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool';
import { classifyAndValidateTarget } from '../../lib/scope';
import { requireAuth, requireRole } from '../middleware/auth';
import { audit } from '../middleware/audit';

export const targetsRouter = Router();
targetsRouter.use(requireAuth);

const createSchema = z.object({
  value: z.string().min(1),
  authorized: z.boolean().optional().default(false),
  authorization_note: z.string().optional(),
});

// Creating a target registers it in the allowlist. It is NOT authorized for
// scanning until `authorized=true` is set (requires analyst/admin role), so
// that scans can never target unreviewed assets.
targetsRouter.post('/', requireRole('admin', 'analyst'), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const { value, authorized, authorization_note } = parsed.data;
  const classification = classifyAndValidateTarget(value);
  if (classification.error) {
    return res.status(400).json({ error: classification.error });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO targets (value, kind, authorized, authorization_note, created_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [
        classification.value,
        classification.kind,
        authorized,
        authorization_note ?? null,
        req.user!.sub,
      ]
    );
    await audit(req, 'target.create', 'target', rows[0].id, { value: classification.value });
    return res.status(201).json(rows[0]);
  } catch (err: any) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Target already exists' });
    }
    throw err;
  }
});

targetsRouter.get('/', async (req, res) => {
  const page = Math.max(parseInt(String(req.query.page ?? '1'), 10), 1);
  const pageSize = Math.min(
    Math.max(parseInt(String(req.query.pageSize ?? '25'), 10), 1),
    200
  );
  const search = String(req.query.search ?? '').trim();
  const params: unknown[] = [];
  let where = '';
  if (search) {
    params.push(`%${search}%`);
    where = `WHERE value ILIKE $${params.length}`;
  }
  const countRes = await pool.query(
    `SELECT COUNT(*)::int AS c FROM targets ${where}`,
    params
  );
  params.push(pageSize, (page - 1) * pageSize);
  const { rows } = await pool.query(
    `SELECT * FROM targets ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  return res.json({
    data: rows,
    pagination: { page, pageSize, total: countRes.rows[0].c },
  });
});

targetsRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM targets WHERE id = $1', [
    req.params.id,
  ]);
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  return res.json(rows[0]);
});

targetsRouter.patch('/:id/authorize', requireRole('admin', 'analyst'), async (req, res) => {
  const schema = z.object({ authorized: z.boolean(), authorization_note: z.string().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { rows } = await pool.query(
    `UPDATE targets SET authorized = $1, authorization_note = COALESCE($2, authorization_note), updated_at = now()
     WHERE id = $3 RETURNING *`,
    [parsed.data.authorized, parsed.data.authorization_note ?? null, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
  await audit(req, 'target.authorize', 'target', req.params.id, parsed.data);
  return res.json(rows[0]);
});

targetsRouter.delete('/:id', requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM targets WHERE id = $1', [req.params.id]);
  await audit(req, 'target.delete', 'target', req.params.id);
  return res.status(204).send();
});
