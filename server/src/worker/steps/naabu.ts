import { PipelineContext, StepResult } from '../../scanners/types';
import { config } from '../../config';
import { runStep } from '../stepRunner';
import { getResolvedIps, upsertPort } from '../db-helpers';

export async function stepNaabu(ctx: PipelineContext): Promise<StepResult> {
  const ips =
    ctx.targetKind === 'domain' ? await getResolvedIps(ctx.scanId) : [ctx.targetValue];
  if (ips.length === 0) {
    return { status: 'skipped', error: 'No IPs to port-scan' };
  }
  return runStep({
    scanId: ctx.scanId,
    toolName: 'naabu',
    binary: 'naabu',
    args: [
      '-json',
      '-silent',
      '-top-ports',
      config.scanner.portScanTopPorts,
      '-scan-type',
      'CONNECT', // no raw sockets / no root required, safer default than SYN
      '-rate',
      '200',
    ],
    stdin: ips.join('\n'),
    evidenceRoot: ctx.evidenceRoot,
    timeoutSec: Math.max(120, ips.length * 30),
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
        const ip = String(obj.ip ?? '');
        const port = Number(obj.port);
        if (!ip || !port) continue;
        await upsertPort(
          ctx.scanId,
          ip,
          port,
          String(obj.protocol ?? 'tcp'),
          null,
          'naabu'
        );
        count += 1;
      }
      return count;
    },
  });
}
