import { Request } from 'express';
import { pool } from '../../db/pool';

export async function audit(
  req: Request,
  action: string,
  resourceType?: string,
  resourceId?: string | number,
  meta: Record<string, unknown> = {}
): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, meta)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        req.user?.sub ?? null,
        action,
        resourceType ?? null,
        resourceId != null ? String(resourceId) : null,
        req.ip,
        JSON.stringify(meta),
      ]
    );
  } catch (err) {
    // Auditing must never crash the request path; log to stderr instead.
    // eslint-disable-next-line no-console
    console.error('[audit] failed to write audit log', err);
  }
}
