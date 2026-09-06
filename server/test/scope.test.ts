import {
  classifyAndValidateTarget,
  isDisallowedIP,
  isValidCidr,
  isValidDomain,
} from '../src/lib/scope';

describe('scope validation', () => {
  test('accepts a valid public domain', () => {
    const result = classifyAndValidateTarget('example.com');
    expect(result.error).toBeUndefined();
    expect(result.kind).toBe('domain');
    expect(result.value).toBe('example.com');
  });

  test('rejects localhost domain', () => {
    const result = classifyAndValidateTarget('localhost');
    expect(result.error).toBeDefined();
  });

  test('rejects malformed domains', () => {
    expect(isValidDomain('not a domain')).toBe(false);
    expect(isValidDomain('-bad.com')).toBe(false);
    expect(isValidDomain('good.example.com')).toBe(true);
  });

  test('rejects loopback IP by default', () => {
    const result = classifyAndValidateTarget('127.0.0.1');
    expect(result.error).toMatch(/not allowed/i);
  });

  test('rejects private RFC1918 ranges by default', () => {
    expect(isDisallowedIP('10.0.0.5')).toBe(true);
    expect(isDisallowedIP('172.16.5.1')).toBe(true);
    expect(isDisallowedIP('192.168.1.1')).toBe(true);
    expect(isDisallowedIP('100.64.0.1')).toBe(true);
  });

  test('rejects cloud metadata endpoint', () => {
    const result = classifyAndValidateTarget('169.254.169.254');
    expect(result.error).toBeDefined();
  });

  test('allows a public IP address', () => {
    expect(isDisallowedIP('8.8.8.8')).toBe(false);
    const result = classifyAndValidateTarget('8.8.8.8');
    expect(result.error).toBeUndefined();
    expect(result.kind).toBe('ip');
  });

  test('validates CIDR notation and blocks private ranges', () => {
    expect(isValidCidr('8.8.8.0/24')).toBe(true);
    expect(isValidCidr('not-a-cidr')).toBe(false);
    const result = classifyAndValidateTarget('10.0.0.0/8');
    expect(result.error).toBeDefined();
  });

  test('rejects empty input', () => {
    const result = classifyAndValidateTarget('   ');
    expect(result.error).toBeDefined();
  });
});
