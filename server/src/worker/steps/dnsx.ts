import { PipelineContext, StepResult } from '../../scanners/types';
import { isDisallowedIP } from '../../lib/scope';
import { runStep } from '../stepRunner';
import { getSubdomainHostnames, logScan, upsertDnsRecord, upsertIp } from '../db-helpers';

export async function stepDnsx(ctx: PipelineContext): Promise<StepResult> {
  const hosts =
    ctx.targetKind === 'domain'
      ? await getSubdomainHostnames(ctx.scanId)
      : [ctx.targetValue];
  if (hosts.length === 0) {
    return { status: 'skipped', error: 'No hostnames to resolve' };
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'dnsx',
    binary: 'dnsx',
    args: ['-json', '-silent', '-a', '-aaaa', '-cname', '-resp'],
    stdin: hosts.join('\n'),
    evidenceRoot: ctx.evidenceRoot,
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
        const host = String(obj.host ?? '').toLowerCase();
        if (!host) continue;
        for (const [key, recordType] of [
          ['a', 'A'],
          ['aaaa', 'AAAA'],
          ['cname', 'CNAME'],
        ] as const) {
          const values = obj[key] as string[] | undefined;
          if (!Array.isArray(values)) continue;
          for (const value of values) {
            await upsertDnsRecord(ctx.scanId, host, recordType, value, 'dnsx');
            count += 1;
            if ((key === 'a' || key === 'aaaa')) {
              if (isDisallowedIP(value)) {
                await logScan(
                  ctx.scanId,
                  `Skipping out-of-scope resolved IP ${value} for ${host}`,
                  'warn'
                );
                continue;
              }
              await upsertIp(ctx.scanId, host, value, 'dnsx');
            }
          }
        }
      }
      return count;
    },
  });
}
