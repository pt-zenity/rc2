export interface PipelineContext {
  scanId: number;
  targetId: number;
  targetValue: string; // domain, IP, or CIDR as stored on the target
  targetKind: 'domain' | 'ip' | 'cidr';
  evidenceRoot: string;
  nucleiHighRisk: boolean;
}

export type StepStatus = 'completed' | 'failed' | 'timeout' | 'skipped';

export interface StepResult {
  status: StepStatus;
  error?: string;
}
