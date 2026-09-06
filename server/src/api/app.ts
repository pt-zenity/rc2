import cors from 'cors';
import express from 'express';
import pinoHttp from 'pino-http';
import { pool } from '../db/pool';
import { authRouter } from './routes/auth';
import { resultsRouter } from './routes/results';
import { scansRouter } from './routes/scans';
import { targetsRouter } from './routes/targets';

export function createApp() {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));
  app.use(pinoHttp({ autoLogging: { ignore: (req) => req.url === '/healthz' } }));

  app.get('/healthz', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      return res.json({ status: 'ok' });
    } catch (err) {
      return res.status(503).json({ status: 'error', error: (err as Error).message });
    }
  });

  app.use('/api/auth', authRouter);
  app.use('/api/targets', targetsRouter);
  app.use('/api/scans', scansRouter);
  app.use('/api/results', resultsRouter);

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
