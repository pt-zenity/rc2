import { StepResult } from '../../scanners/types';
import { PipelineContext } from '../../scanners/types';
import { runStep } from '../stepRunner';
import { upsertSubdomain } from '../db-helpers';

export async function stepSubfinder(ctx: PipelineContext): Promise<StepResult> {
  if (ctx.targetKind !== 'domain') {
    return { status: 'skipped', error: 'subfinder only applies to domain targets' };
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'subfinder',
    binary: 'subfinder',
    args: ['-d', ctx.targetValue, '-json', '-silent', '-timeout', '15'],
    evidenceRoot: ctx.evidenceRoot,
    parse: async (stdout) => {
      let count = 0;
      for (const line of stdout.split('\n')) {
        if (!line.trim()) continue;
        try {
          const obj = JSON.parse(line);
          const host = obj.host as string | undefined;
          if (host) {
            await upsertSubdomain(ctx.scanId, ctx.targetId, host.toLowerCase(), 'subfinder');
            count += 1;
          }
        } catch {
          // ignore malformed line, subfinder occasionally logs non-JSON noise
        }
      }
      // Ensure the apex domain itself is always considered part of the
      // attack surface even if subfinder finds nothing else.
      await upsertSubdomain(ctx.scanId, ctx.targetId, ctx.targetValue, 'seed');
      return count;
    },
  });
}
