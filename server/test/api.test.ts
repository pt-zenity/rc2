import request from 'supertest';
import { createApp } from '../src/api/app';
import { pool } from '../src/db/pool';
import { scanQueue, connection } from '../src/worker/queue';

const app = createApp();
const suffix = Date.now();

function bearer(token: string): string {
  return ['Bearer', token].join(' ');
}

describe('API integration', () => {
  afterAll(async () => {
    await scanQueue.close();
    await connection.quit();
    await pool.end();
  });

  let token: string;

  test('registers a new user and receives a JWT', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: `admin-${suffix}@example.com`, password: 'SuperSecretPass123' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    // Promote to admin regardless of registration order so this suite is
    // deterministic even when run against a database that already has users.
    await pool.query("UPDATE users SET role = 'admin' WHERE id = $1", [res.body.user.id]);
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: `admin-${suffix}@example.com`, password: 'SuperSecretPass123' });
    token = loginRes.body.token;
  });

  test('rejects login with wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: `admin-${suffix}@example.com`, password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('rejects creating a target without auth', async () => {
    const res = await request(app).post('/api/targets').send({ value: 'example.com' });
    expect(res.status).toBe(401);
  });

  test('rejects private/loopback IP targets (SSRF protection)', async () => {
    const res = await request(app)
      .post('/api/targets')
      .set('Authorization', bearer(token))
      .send({ value: '127.0.0.1' });
    expect(res.status).toBe(400);
  });

  let targetId: number;

  test('creates a valid target as unauthorized by default', async () => {
    const res = await request(app)
      .post('/api/targets')
      .set('Authorization', bearer(token))
      .send({ value: `test-${suffix}.example.com` });
    expect(res.status).toBe(201);
    expect(res.body.authorized).toBe(false);
    targetId = res.body.id;
  });

  test('refuses to queue a scan against an unauthorized target', async () => {
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', bearer(token))
      .send({ target_id: targetId });
    expect(res.status).toBe(403);
  });

  test('allows queuing a scan once the target is authorized', async () => {
    const authRes = await request(app)
      .patch(`/api/targets/${targetId}/authorize`)
      .set('Authorization', bearer(token))
      .send({ authorized: true, authorization_note: 'test lab asset' });
    expect(authRes.status).toBe(200);

    const scanRes = await request(app)
      .post('/api/scans')
      .set('Authorization', bearer(token))
      .send({ target_id: targetId, tools: ['dnsx'] });
    expect(scanRes.status).toBe(201);
    expect(scanRes.body.status).toBe('queued');
  });

  test('lists targets with pagination envelope', async () => {
    const res = await request(app).get('/api/targets').set('Authorization', bearer(token));
    expect(res.status).toBe(200);
    expect(res.body.pagination).toBeDefined();
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  test('rejects high-risk nuclei templates when disabled by server config', async () => {
    const res = await request(app)
      .post('/api/scans')
      .set('Authorization', bearer(token))
      .send({ target_id: targetId, nuclei_high_risk: true });
    expect(res.status).toBe(403);
  });
});
