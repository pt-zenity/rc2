import { PipelineContext, StepResult } from '../../scanners/types';
import { config } from '../../config';
import { runStep } from '../stepRunner';
import { getLiveHostUrls, upsertFinding } from '../db-helpers';

// Vulnerability scanning with the official nuclei-templates corpus.
// Destructive/high-risk categories (dos, fuzz, intrusive, brute-force,
// rce-exploit) are excluded by default and can only run when an admin
// explicitly enables ENABLE_HIGH_RISK_TEMPLATES and requests it per-scan.
export async function stepNuclei(ctx: PipelineContext): Promise<StepResult> {
  const urls = await getLiveHostUrls(ctx.scanId);
  if (urls.length === 0) {
    return { status: 'skipped', error: 'No live hosts to scan for vulnerabilities' };
  }
  const args = [
    '-jsonl',
    '-silent',
    '-templates',
    config.scanner.nucleiTemplatesDir,
    '-severity',
    config.scanner.nucleiSeverities,
    '-rate-limit',
    String(config.scanner.nucleiRateLimit),
    '-timeout',
    '10',
  ];
  if (!ctx.nucleiHighRisk) {
    args.push('-etags', config.scanner.nucleiExcludeTags);
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'nuclei',
    binary: 'nuclei',
    args,
    stdin: urls.join('\n'),
    evidenceRoot: ctx.evidenceRoot,
    timeoutSec: Math.max(180, urls.length * 30),
    parse: async (stdout, evidenceId) => {
      let count = 0;
      for (const line of stdout.split('\n')) {
        if (!line.trim()) continue;
        let obj: Record<string, any>;
        try {
          obj = JSON.parse(line);
        } catch {
          continue;
        }
        const info = obj.info ?? {};
        await upsertFinding(
          ctx.scanId,
          ctx.targetId,
          'nuclei',
          obj['template-id'] ?? obj.templateID ?? null,
          info.name ?? obj['template-id'] ?? 'Unknown finding',
          (info.severity ?? 'unknown').toLowerCase(),
          obj.host ?? null,
          obj.ip ?? null,
          obj['matched-at'] ?? obj.matched ?? obj.host ?? null,
          info.description ?? null,
          typeof obj['extracted-results'] !== 'undefined'
            ? JSON.stringify(obj['extracted-results'])
            : (obj['curl-command'] ?? null),
          info.remediation ?? null,
          Array.isArray(info.reference) ? info.reference : info.reference ? [info.reference] : [],
          evidenceId
        );
        count += 1;
      }
      return count;
    },
  });
}
