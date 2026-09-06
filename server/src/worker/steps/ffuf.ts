import { PipelineContext, StepResult } from '../../scanners/types';
import { config } from '../../config';
import { runStep } from '../stepRunner';
import { getLiveHostUrls, upsertUrl } from '../db-helpers';

const MAX_FFUF_HOSTS = 3; // bounded/controlled directory discovery, not a full crawl

export async function stepFfuf(ctx: PipelineContext): Promise<StepResult> {
  const urls = (await getLiveHostUrls(ctx.scanId)).slice(0, MAX_FFUF_HOSTS);
  if (urls.length === 0) {
    return { status: 'skipped', error: 'No live hosts for directory discovery' };
  }
  let anyCompleted = false;
  let lastError = '';
  for (const url of urls) {
    const target = `${url.replace(/\/$/, '')}/FUZZ`;
    const result = await runStep({
      scanId: ctx.scanId,
      toolName: 'ffuf',
      binary: 'ffuf',
      args: [
        '-u',
        target,
        '-w',
        config.scanner.ffufWordlist,
        '-json',
        '-rate',
        String(config.scanner.ffufRateLimit),
        '-timeout',
        '10',
        '-maxtime',
        '60',
      ],
      evidenceRoot: ctx.evidenceRoot,
      timeoutSec: 90,
      parse: async (stdout) => {
        let count = 0;
        for (const line of stdout.split('\n')) {
          if (!line.trim()) continue;
          let obj: Record<string, unknown>;
          try {
            obj = JSON.parse(line);
          } catch {
            continue;
          }
          const foundUrl = obj.url as string | undefined;
          if (!foundUrl) continue;
          await upsertUrl(
            ctx.scanId,
            foundUrl,
            (obj.status as number) ?? null,
            (obj.length as number) ?? null,
            'ffuf'
          );
          count += 1;
        }
        return count;
      },
    });
    if (result.status === 'completed') anyCompleted = true;
    if (result.error) lastError = result.error;
  }
  return anyCompleted ? { status: 'completed' } : { status: 'failed', error: lastError };
}
