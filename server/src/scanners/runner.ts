import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export interface RunResult {
  exitCode: number | null;
  timedOut: boolean;
  cancelled: boolean;
  stdout: string;
  stderr: string;
  stdoutPath: string;
  stderrPath: string;
  durationMs: number;
}

export interface RunOptions {
  args: string[];
  timeoutSec: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  evidenceDir: string;
  toolName: string;
  onCancelCheck?: () => Promise<boolean>; // returns true if the scan was cancelled
  stdin?: string; // optional data piped to the process's stdin
}

/**
 * Executes a scanner binary as a child process with an enforced timeout,
 * captures stdout/stderr to disk (real evidence, never fabricated), and
 * resolves with the outcome rather than throwing, so a single scanner
 * failure never crashes the pipeline or destroys other scanners' results.
 */
export async function runTool(bin: string, opts: RunOptions): Promise<RunResult> {
  const start = Date.now();
  fs.mkdirSync(opts.evidenceDir, { recursive: true });
  const stdoutPath = path.join(opts.evidenceDir, `${opts.toolName}.stdout.log`);
  const stderrPath = path.join(opts.evidenceDir, `${opts.toolName}.stderr.log`);
  const stdoutStream = fs.createWriteStream(stdoutPath);
  const stderrStream = fs.createWriteStream(stderrPath);

  return new Promise<RunResult>((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let cancelled = false;
    let settled = false;

    const child = spawn(bin, opts.args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
    });

    if (opts.stdin !== undefined) {
      child.stdin.write(opts.stdin);
    }
    child.stdin.end();

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, opts.timeoutSec * 1000);

    let cancelInterval: NodeJS.Timeout | undefined;
    if (opts.onCancelCheck) {
      cancelInterval = setInterval(async () => {
        const wasCancelled = await opts.onCancelCheck!();
        if (wasCancelled) {
          cancelled = true;
          child.kill('SIGKILL');
        }
      }, 2000);
    }

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
      stdoutStream.write(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
      stderrStream.write(chunk);
    });

    const finish = (exitCode: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (cancelInterval) clearInterval(cancelInterval);
      stdoutStream.end();
      stderrStream.end();
      resolve({
        exitCode,
        timedOut,
        cancelled,
        stdout,
        stderr,
        stdoutPath,
        stderrPath,
        durationMs: Date.now() - start,
      });
    };

    child.on('error', () => finish(-1));
    child.on('close', (code) => finish(code));
  });
}
