import * as path from 'path';
import { config } from '../config';
import { runTool } from '../scanners/runner';
import { StepResult } from '../scanners/types';
import {
  createScanJob,
  isScanCancelled,
  logScan,
  recordEvidence,
  updateScanJob,
} from './db-helpers';

export interface StepDefinition {
  scanId: number;
  toolName: string;
  binary: string;
  args: string[];
  stdin?: string;
  evidenceRoot: string;
  timeoutSec?: number;
  maxAttempts?: number;
  parse: (stdout: string, evidenceId: number | null) => Promise<number>;
}

/**
 * Runs a single scanner tool as one scan_job: records lifecycle
 * (queued -> running -> completed/failed/timeout), enforces a timeout,
 * retries transient failures up to maxAttempts, stores raw stdout/stderr as
 * evidence, and hands the raw stdout to a tool-specific parser. A failure in
 * this step never throws upward - the pipeline continues with other tools.
 */
export async function runStep(def: StepDefinition): Promise<StepResult> {
  const timeoutSec = def.timeoutSec ?? config.scanner.defaultTimeoutSec;
  const maxAttempts = def.maxAttempts ?? config.scanner.maxRetries + 1;
  const jobId = await createScanJob(def.scanId, def.toolName, timeoutSec, maxAttempts);
  const evidenceDir = path.join(def.evidenceRoot, def.toolName);

  const binaryPath = config.binDir ? path.join(config.binDir, def.binary) : def.binary;

  let lastError = '';
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (await isScanCancelled(def.scanId)) {
      await updateScanJob(jobId, { status: 'cancelled' });
      return { status: 'skipped', error: 'Scan cancelled' };
    }
    await updateScanJob(jobId, {
      status: 'running',
      attempt,
      command: `${def.binary} ${def.args.join(' ')}`,
      started_at: new Date(),
    });
    await logScan(def.scanId, `Starting ${def.toolName} (attempt ${attempt}/${maxAttempts})`, 'info', jobId);

    let result;
    try {
      result = await runTool(binaryPath, {
        args: def.args,
        stdin: def.stdin,
        timeoutSec,
        evidenceDir,
        toolName: def.toolName,
        onCancelCheck: () => isScanCancelled(def.scanId),
      });
    } catch (err) {
      lastError = `Failed to spawn ${def.binary}: ${(err as Error).message}`;
      await logScan(def.scanId, lastError, 'error', jobId);
      await updateScanJob(jobId, { status: 'failed', error: lastError, finished_at: new Date() });
      continue;
    }

    const stdoutEvidenceId = await recordEvidence(
      def.scanId,
      jobId,
      def.toolName,
      'raw_output',
      result.stdoutPath
    );
    await recordEvidence(def.scanId, jobId, def.toolName, 'stderr', result.stderrPath);

    if (result.cancelled) {
      await logScan(def.scanId, `${def.toolName} cancelled by user`, 'warn', jobId);
      await updateScanJob(jobId, {
        status: 'cancelled',
        finished_at: new Date(),
        exit_code: result.exitCode ?? undefined,
      });
      return { status: 'skipped', error: 'Cancelled' };
    }

    if (result.timedOut) {
      lastError = `${def.toolName} timed out after ${timeoutSec}s`;
      await logScan(def.scanId, lastError, 'warn', jobId);
      await updateScanJob(jobId, {
        status: 'timeout',
        error: lastError,
        finished_at: new Date(),
        exit_code: result.exitCode ?? undefined,
      });
      if (attempt < maxAttempts) continue;
      return { status: 'timeout', error: lastError };
    }

    if (result.exitCode !== 0 && result.exitCode !== null) {
      lastError = `${def.toolName} exited with code ${result.exitCode}: ${result.stderr.slice(0, 500)}`;
      await logScan(def.scanId, lastError, 'warn', jobId);
      // Some tools (e.g. httpx/nuclei) legitimately return a non-zero code
      // even when they produced partial useful output, so we still attempt
      // to parse whatever stdout was captured before deciding pass/fail.
    }

    let parsedCount = 0;
    try {
      parsedCount = await def.parse(result.stdout, stdoutEvidenceId);
    } catch (err) {
      lastError = `Failed to parse ${def.toolName} output: ${(err as Error).message}`;
      await logScan(def.scanId, lastError, 'error', jobId);
    }

    if (result.exitCode !== 0 && result.exitCode !== null && parsedCount === 0) {
      await updateScanJob(jobId, {
        status: 'failed',
        error: lastError || `${def.toolName} produced no output`,
        exit_code: result.exitCode,
        finished_at: new Date(),
      });
      if (attempt < maxAttempts) continue;
      return { status: 'failed', error: lastError };
    }

    await updateScanJob(jobId, {
      status: 'completed',
      exit_code: result.exitCode ?? undefined,
      finished_at: new Date(),
    });
    await logScan(
      def.scanId,
      `${def.toolName} completed: ${parsedCount} result(s) parsed`,
      'info',
      jobId
    );
    return { status: 'completed' };
  }

  return { status: 'failed', error: lastError };
}
