import { PipelineContext, StepResult } from '../../scanners/types';
import { runStep } from '../stepRunner';
import { getLiveHostUrls, upsertUrl } from '../db-helpers';

export async function stepKatana(ctx: PipelineContext): Promise<StepResult> {
  const urls = await getLiveHostUrls(ctx.scanId);
  if (urls.length === 0) {
    return { status: 'skipped', error: 'No live hosts to crawl' };
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'katana',
    binary: 'katana',
    args: ['-jsonl', '-silent', '-d', '2', '-timeout', '10'],
    stdin: urls.join('\n'),
    evidenceRoot: ctx.evidenceRoot,
    timeoutSec: Math.max(120, urls.length * 20),
    parse: async (stdout) => {
      let count = 0;
      for (const line of stdout.split('\n')) {
        if (!line.trim()) continue;
        let obj: Record<string, any>;
        try {
          obj = JSON.parse(line);
        } catch {
          continue;
        }
        const url = obj?.request?.endpoint;
        if (!url) continue;
        const statusCode = obj?.response?.status_code ?? null;
        const contentLength = obj?.response?.headers?.content_length
          ? parseInt(obj.response.headers.content_length, 10)
          : null;
        await upsertUrl(ctx.scanId, url, statusCode, contentLength, 'katana');
        count += 1;
      }
      return count;
    },
  });
}
