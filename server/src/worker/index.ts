import { Worker } from 'bullmq';
import { connection, SCAN_QUEUE_NAME, ScanJobData } from './queue';
import { executeScan } from './pipeline';
import { config } from '../config';
import { pool } from '../db/pool';

const worker = new Worker<ScanJobData>(
  SCAN_QUEUE_NAME,
  async (job) => {
    try {
      await executeScan(job.data.scanId);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[worker] scan ${job.data.scanId} crashed`, err);
      await pool.query(
        `UPDATE scans SET status = 'failed', error = $2, finished_at = now() WHERE id = $1 AND status != 'cancelled'`,
        [job.data.scanId, (err as Error).message]
      );
      throw err;
    }
  },
  {
    connection,
    concurrency: config.scanner.maxConcurrentJobsPerScan,
  }
);

worker.on('completed', (job) => {
  // eslint-disable-next-line no-console
  console.log(`[worker] scan ${job.data.scanId} pipeline finished`);
});

worker.on('failed', (job, err) => {
  // eslint-disable-next-line no-console
  console.error(`[worker] scan ${job?.data?.scanId} pipeline failed`, err);
});

// eslint-disable-next-line no-console
console.log('[worker] listening for scan jobs');
