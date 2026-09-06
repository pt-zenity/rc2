import { comparePassword, hashPassword, signToken, verifyToken } from '../src/lib/auth';

describe('auth helpers', () => {
  test('hashes and verifies passwords', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');
    expect(hash).not.toBe('correct-horse-battery-staple');
    await expect(comparePassword('correct-horse-battery-staple', hash)).resolves.toBe(true);
    await expect(comparePassword('wrong-password', hash)).resolves.toBe(false);
  });

  test('signs and verifies a JWT round-trip', () => {
    const token = signToken({ sub: 1, email: 'user@example.com', role: 'analyst' });
    const payload = verifyToken(token);
    expect(payload.sub).toBe(1);
    expect(payload.email).toBe('user@example.com');
    expect(payload.role).toBe('analyst');
  });

  test('rejects a tampered token', () => {
    const token = signToken({ sub: 1, email: 'user@example.com', role: 'analyst' });
    expect(() => verifyToken(`${token}tampered`)).toThrow();
  });
});
