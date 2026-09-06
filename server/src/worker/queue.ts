import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import { config } from '../config';

export const connection = new IORedis(config.redisUrl, {
  maxRetriesPerRequest: null,
});

export const SCAN_QUEUE_NAME = 'recon-scans';

export const scanQueue = new Queue(SCAN_QUEUE_NAME, { connection });

export interface ScanJobData {
  scanId: number;
}
