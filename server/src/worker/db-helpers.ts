import * as fs from 'fs';
import { PoolClient } from 'pg';
import { pool } from '../db/pool';

export async function createScanJob(
  scanId: number,
  toolName: string,
  timeoutSec: number,
  maxAttempts: number
): Promise<number> {
  const { rows } = await pool.query(
    `INSERT INTO scan_jobs (scan_id, tool_name, status, timeout_sec, max_attempts)
     VALUES ($1, $2, 'queued', $3, $4) RETURNING id`,
    [scanId, toolName, timeoutSec, maxAttempts]
  );
  return rows[0].id;
}

export async function updateScanJob(
  jobId: number,
  fields: Partial<{
    status: string;
    attempt: number;
    exit_code: number | null;
    command: string;
    error: string | null;
    started_at: Date;
    finished_at: Date;
  }>
): Promise<void> {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const setClause = keys.map((k, i) => `${k} = $${i + 2}`).join(', ');
  await pool.query(`UPDATE scan_jobs SET ${setClause} WHERE id = $1`, [
    jobId,
    ...keys.map((k) => (fields as Record<string, unknown>)[k]),
  ]);
}

export async function logScan(
  scanId: number,
  message: string,
  level: 'debug' | 'info' | 'warn' | 'error' = 'info',
  scanJobId?: number
): Promise<void> {
  await pool.query(
    `INSERT INTO scan_logs (scan_id, scan_job_id, level, message) VALUES ($1, $2, $3, $4)`,
    [scanId, scanJobId ?? null, level, message]
  );
}

export async function recordEvidence(
  scanId: number,
  scanJobId: number,
  toolName: string,
  kind: 'stdout' | 'stderr' | 'raw_output',
  filePath: string
): Promise<number> {
  let byteSize = 0;
  try {
    byteSize = fs.statSync(filePath).size;
  } catch {
    byteSize = 0;
  }
  const { rows } = await pool.query(
    `INSERT INTO evidence (scan_id, scan_job_id, tool_name, kind, file_path, byte_size)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [scanId, scanJobId, toolName, kind, filePath, byteSize]
  );
  return rows[0].id;
}

export async function upsertSubdomain(
  scanId: number,
  targetId: number,
  hostname: string,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO subdomains (scan_id, target_id, hostname, source_tool)
     VALUES ($1, $2, $3, $4) ON CONFLICT (scan_id, hostname) DO NOTHING`,
    [scanId, targetId, hostname, sourceTool]
  );
}

export async function upsertDnsRecord(
  scanId: number,
  hostname: string,
  recordType: string,
  value: string,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO dns_records (scan_id, hostname, record_type, value, source_tool)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (scan_id, hostname, record_type, value) DO NOTHING`,
    [scanId, hostname, recordType, value, sourceTool]
  );
}

export async function upsertIp(
  scanId: number,
  hostname: string | null,
  ip: string,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO ip_addresses (scan_id, hostname, ip, source_tool)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (scan_id, hostname, ip) DO NOTHING`,
    [scanId, hostname, ip, sourceTool]
  );
}

export async function upsertPort(
  scanId: number,
  ip: string,
  port: number,
  protocol: string,
  service: string | null,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO ports (scan_id, ip, port, protocol, service, source_tool)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (scan_id, ip, port, protocol) DO NOTHING`,
    [scanId, ip, port, protocol, service, sourceTool]
  );
}

export async function upsertHttpProbe(
  scanId: number,
  hostname: string,
  url: string,
  statusCode: number | null,
  title: string | null,
  webserver: string | null,
  contentLength: number | null,
  tlsJson: unknown,
  tech: string[],
  sourceTool: string
): Promise<number | null> {
  const { rows } = await pool.query(
    `INSERT INTO http_probes (scan_id, hostname, url, status_code, title, webserver, content_length, tls_json, tech, source_tool)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT (scan_id, url) DO UPDATE SET status_code = EXCLUDED.status_code
     RETURNING id`,
    [
      scanId,
      hostname,
      url,
      statusCode,
      title,
      webserver,
      contentLength,
      tlsJson ? JSON.stringify(tlsJson) : null,
      JSON.stringify(tech),
      sourceTool,
    ]
  );
  return rows[0]?.id ?? null;
}

export async function upsertTechnology(
  scanId: number,
  httpProbeId: number | null,
  url: string,
  name: string,
  version: string | null,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO technologies (scan_id, http_probe_id, url, name, version, source_tool)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (scan_id, url, name) DO NOTHING`,
    [scanId, httpProbeId, url, name, version, sourceTool]
  );
}

export async function upsertUrl(
  scanId: number,
  url: string,
  statusCode: number | null,
  contentLength: number | null,
  sourceTool: string
): Promise<void> {
  await pool.query(
    `INSERT INTO urls (scan_id, url, status_code, content_length, source_tool)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (scan_id, url, source_tool) DO NOTHING`,
    [scanId, url, statusCode, contentLength, sourceTool]
  );
}

export async function upsertFinding(
  scanId: number,
  targetId: number,
  toolName: string,
  templateId: string | null,
  name: string,
  severity: string,
  hostname: string | null,
  ip: string | null,
  matchedUrl: string | null,
  description: string | null,
  evidenceSnippet: string | null,
  remediation: string | null,
  reference: string[],
  evidenceId: number | null
): Promise<void> {
  await pool.query(
    `INSERT INTO findings (scan_id, target_id, tool_name, template_id, name, severity, hostname, ip, matched_url, description, evidence_snippet, remediation, reference, evidence_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     ON CONFLICT (scan_id, tool_name, template_id, matched_url) DO NOTHING`,
    [
      scanId,
      targetId,
      toolName,
      templateId,
      name,
      severity,
      hostname,
      ip,
      matchedUrl,
      description,
      evidenceSnippet,
      remediation,
      JSON.stringify(reference),
      evidenceId,
    ]
  );
}

export async function isScanCancelled(scanId: number): Promise<boolean> {
  const { rows } = await pool.query('SELECT status FROM scans WHERE id = $1', [scanId]);
  return rows[0]?.status === 'cancelled';
}

export type { PoolClient };

export async function getSubdomainHostnames(scanId: number): Promise<string[]> {
  const { rows } = await pool.query('SELECT DISTINCT hostname FROM subdomains WHERE scan_id = $1', [scanId]);
  return rows.map((r) => r.hostname);
}

export async function getResolvedIps(scanId: number): Promise<string[]> {
  const { rows } = await pool.query('SELECT DISTINCT ip FROM ip_addresses WHERE scan_id = $1', [scanId]);
  return rows.map((r) => r.ip);
}

export async function getLiveHostUrls(scanId: number): Promise<string[]> {
  const { rows } = await pool.query('SELECT DISTINCT url FROM http_probes WHERE scan_id = $1', [scanId]);
  return rows.map((r) => r.url);
}

export async function getDistinctPorts(scanId: number): Promise<number[]> {
  const { rows } = await pool.query('SELECT DISTINCT port FROM ports WHERE scan_id = $1', [scanId]);
  return rows.map((r) => r.port);
}
