import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool';
import { comparePassword, hashPassword, signToken } from '../../lib/auth';
import { audit } from '../middleware/audit';

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(10),
});

// First registered user becomes admin; subsequent self-registrations default
// to the lowest-privilege 'viewer' role. Promote additional admins manually
// via the database or a future admin-management endpoint.
authRouter.post('/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const { email, password } = parsed.data;

  const existingCount = await pool.query('SELECT COUNT(*)::int AS c FROM users');
  const role = existingCount.rows[0].c === 0 ? 'admin' : 'viewer';

  const passwordHash = await hashPassword(password);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)
       RETURNING id, email, role`,
      [email.toLowerCase(), passwordHash, role]
    );
    const user = rows[0];
    const token = signToken({ sub: user.id, email: user.email, role: user.role });
    await audit(req, 'user.register', 'user', user.id);
    return res.status(201).json({ token, user });
  } catch (err: any) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    throw err;
  }
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

authRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const { email, password } = parsed.data;
  const { rows } = await pool.query(
    'SELECT id, email, password_hash, role FROM users WHERE email = $1',
    [email.toLowerCase()]
  );
  if (rows.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const user = rows[0];
  const ok = await comparePassword(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = signToken({ sub: user.id, email: user.email, role: user.role });
  await audit(req, 'user.login', 'user', user.id);
  return res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
});
