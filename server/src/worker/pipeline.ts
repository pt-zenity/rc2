import * as path from 'path';
import { pool } from '../db/pool';
import { config } from '../config';
import { PipelineContext, StepResult } from '../scanners/types';
import { logScan } from './db-helpers';
import { stepSubfinder } from './steps/subfinder';
import { stepDnsx } from './steps/dnsx';
import { stepHttpx } from './steps/httpx';
import { stepNaabu } from './steps/naabu';
import { stepKatana } from './steps/katana';
import { stepGau } from './steps/gau';
import { stepFfuf } from './steps/ffuf';
import { stepNuclei } from './steps/nuclei';

type StepFn = (ctx: PipelineContext) => Promise<StepResult>;

// Fixed execution order: each stage's output seeds the input of the next,
// matching the target -> subdomain -> ip -> port -> url -> tech -> finding
// data model. A tool disabled in scan.config.tools is skipped entirely.
const PIPELINE: Array<{ name: string; run: StepFn }> = [
  { name: 'subfinder', run: stepSubfinder },
  { name: 'dnsx', run: stepDnsx },
  { name: 'naabu', run: stepNaabu },
  { name: 'httpx', run: stepHttpx },
  { name: 'katana', run: stepKatana },
  { name: 'gau', run: stepGau },
  { name: 'ffuf', run: stepFfuf },
  { name: 'nuclei', run: stepNuclei },
];

export async function executeScan(scanId: number): Promise<void> {
  const scanRes = await pool.query('SELECT * FROM scans WHERE id = $1', [scanId]);
  if (scanRes.rows.length === 0) throw new Error(`Scan ${scanId} not found`);
  const scan = scanRes.rows[0];

  if (scan.status === 'cancelled') return;

  const targetRes = await pool.query('SELECT * FROM targets WHERE id = $1', [scan.target_id]);
  const target = targetRes.rows[0];
  if (!target || !target.authorized) {
    await pool.query(
      `UPDATE scans SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`,
      [scanId, 'Target is not authorized for scanning']
    );
    return;
  }

  await pool.query(
    `UPDATE scans SET status = 'running', started_at = now() WHERE id = $1`,
    [scanId]
  );
  await logScan(scanId, `Scan started for target ${target.value}`);

  const ctx: PipelineContext = {
    scanId,
    targetId: target.id,
    targetValue: target.value,
    targetKind: target.kind,
    evidenceRoot: path.join(config.evidenceDir, String(scanId)),
    nucleiHighRisk: Boolean(scan.config?.nuclei_high_risk),
  };

  const enabledTools: string[] = scan.config?.tools ?? PIPELINE.map((s) => s.name);

  const outcomes: Record<string, StepResult> = {};

  for (const step of PIPELINE) {
    const current = await pool.query('SELECT status FROM scans WHERE id = $1', [scanId]);
    if (current.rows[0].status === 'cancelled') {
      await logScan(scanId, 'Scan cancelled, stopping pipeline', 'warn');
      break;
    }
    if (!enabledTools.includes(step.name)) {
      outcomes[step.name] = { status: 'skipped', error: 'Disabled for this scan' };
      continue;
    }
    try {
      outcomes[step.name] = await step.run(ctx);
    } catch (err) {
      const message = (err as Error).message;
      await logScan(scanId, `Unexpected error running ${step.name}: ${message}`, 'error');
      outcomes[step.name] = { status: 'failed', error: message };
    }
  }

  const finalScan = await pool.query('SELECT status FROM scans WHERE id = $1', [scanId]);
  if (finalScan.rows[0].status === 'cancelled') {
    return;
  }

  const statuses = Object.values(outcomes).map((o) => o.status);
  const completedCount = statuses.filter((s) => s === 'completed').length;
  const failedCount = statuses.filter((s) => s === 'failed' || s === 'timeout').length;

  let finalStatus: string;
  if (completedCount === 0 && failedCount > 0) {
    finalStatus = 'failed';
  } else if (failedCount > 0) {
    finalStatus = 'partial';
  } else {
    finalStatus = 'completed';
  }

  await pool.query(
    `UPDATE scans SET status = $2, finished_at = now() WHERE id = $1`,
    [scanId, finalStatus]
  );
  await logScan(scanId, `Scan finished with status: ${finalStatus}`);
}
