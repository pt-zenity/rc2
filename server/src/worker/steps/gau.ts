import { PipelineContext, StepResult } from '../../scanners/types';
import { runStep } from '../stepRunner';
import { upsertUrl } from '../db-helpers';

// gau queries public passive archives (Wayback Machine, Common Crawl, OTX,
// URLScan) for historical URLs. It never sends requests directly to the
// target, so it complements the active scanners with passive
// attack-surface data.
export async function stepGau(ctx: PipelineContext): Promise<StepResult> {
  if (ctx.targetKind !== 'domain') {
    return { status: 'skipped', error: 'gau only applies to domain targets' };
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'gau',
    binary: 'gau',
    args: [ctx.targetValue, '--json', '--subs', '--timeout', '30'],
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
        const url = obj.url as string | undefined;
        if (!url) continue;
        await upsertUrl(ctx.scanId, url, null, null, 'gau');
        count += 1;
      }
      return count;
    },
  });
}
