import { PipelineContext, StepResult } from '../../scanners/types';
import { runStep } from '../stepRunner';
import {
  getDistinctPorts,
  getSubdomainHostnames,
  upsertHttpProbe,
  upsertTechnology,
} from '../db-helpers';

export async function stepHttpx(ctx: PipelineContext): Promise<StepResult> {
  const hosts =
    ctx.targetKind === 'domain'
      ? await getSubdomainHostnames(ctx.scanId)
      : [ctx.targetValue];
  if (hosts.length === 0) {
    return { status: 'skipped', error: 'No hostnames to probe' };
  }
  // Chain port discovery into HTTP probing: in addition to the default
  // 80/443, also probe any non-standard ports naabu found open so real
  // web services on unusual ports are not missed.
  const discoveredPorts = (await getDistinctPorts(ctx.scanId)).filter(
    (p) => ![22, 25, 3306, 5432, 6379, 27017].includes(p)
  );
  const args = [
    '-json',
    '-silent',
    '-sc',
    '-title',
    '-server',
    '-td',
    '-tls-grab',
    '-cl',
    '-timeout',
    '10',
  ];
  if (discoveredPorts.length > 0) {
    args.push('-ports', discoveredPorts.join(','));
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'httpx',
    binary: 'httpx',
    args,
    stdin: hosts.join('\n'),
    evidenceRoot: ctx.evidenceRoot,
    timeoutSec: Math.max(60, hosts.length * 5),
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
        const url = String(obj.url ?? '');
        const host = String(obj.host ?? obj.input ?? '');
        if (!url || !host) continue;
        const techList = Array.isArray(obj.tech) ? (obj.tech as string[]) : [];
        const probeId = await upsertHttpProbe(
          ctx.scanId,
          host,
          url,
          (obj.status_code as number) ?? null,
          (obj.title as string) ?? null,
          (obj.webserver as string) ?? null,
          (obj.content_length as number) ?? null,
          obj.tls ?? null,
          techList,
          'httpx'
        );
        for (const entry of techList) {
          const [name, version] = entry.split(':');
          await upsertTechnology(ctx.scanId, probeId, url, name, version ?? null, 'httpx');
        }
        count += 1;
      }
      return count;
    },
  });
}
