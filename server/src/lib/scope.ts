import * as dns from 'dns';
import { isIP } from 'net';
import { config } from '../config';

// Blocks scanning of loopback, link-local, private/internal networks and
// common cloud metadata endpoints unless explicitly overridden via env vars
// (which should only ever be enabled in an isolated lab environment).
const METADATA_HOSTNAMES = new Set([
  '169.254.169.254', // AWS/GCP/Azure/DO metadata
  'metadata.google.internal',
  'metadata.azure.com',
]);

export interface ScopeCheckResult {
  allowed: boolean;
  reason?: string;
}

function ipToLong(ip: string): number {
  return ip
    .split('.')
    .reduce((acc, octet) => acc * 256 + parseInt(octet, 10), 0);
}

function inCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(range) & mask);
}

const PRIVATE_V4_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local / metadata
  '100.64.0.0/10', // carrier-grade NAT
  '0.0.0.0/8',
];

export function isPrivateOrReservedIPv4(ip: string): boolean {
  if (isIP(ip) !== 4) return false;
  return PRIVATE_V4_RANGES.some((cidr) => inCidr(ip, cidr));
}

export function isLoopbackOrLinkLocalV6(ip: string): boolean {
  if (isIP(ip) !== 6) return false;
  const normalized = ip.toLowerCase();
  return (
    normalized === '::1' ||
    normalized.startsWith('fe80:') ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd')
  );
}

export function isDisallowedIP(ip: string): boolean {
  if (METADATA_HOSTNAMES.has(ip)) return true;
  if (config.allowLoopbackTargets && config.allowPrivateTargets) return false;
  const v4blocked = isPrivateOrReservedIPv4(ip);
  const v6blocked = isLoopbackOrLinkLocalV6(ip);
  return v4blocked || v6blocked;
}

const DOMAIN_REGEX =
  /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export function isValidDomain(value: string): boolean {
  return DOMAIN_REGEX.test(value) && value.length <= 253;
}

export function isValidCidr(value: string): boolean {
  const [ip, bits] = value.split('/');
  if (!bits) return false;
  if (isIP(ip) !== 4) return false;
  const n = parseInt(bits, 10);
  return n >= 0 && n <= 32;
}

/**
 * Validates a target string supplied by a user when registering an
 * authorized asset. Rejects malformed input and, unless explicitly
 * overridden for lab use, rejects private/loopback/metadata addresses so
 * that internal infrastructure can never be added as a scan target.
 */
export function classifyAndValidateTarget(rawValue: string): {
  kind: 'domain' | 'ip' | 'cidr';
  value: string;
  error?: string;
} {
  const value = rawValue.trim().toLowerCase();
  if (!value) return { kind: 'domain', value, error: 'Target is empty' };

  if (isIP(value)) {
    if (isDisallowedIP(value) && METADATA_HOSTNAMES.has(value)) {
      return { kind: 'ip', value, error: 'Metadata endpoints are not allowed' };
    }
    if (isDisallowedIP(value)) {
      return {
        kind: 'ip',
        value,
        error:
          'Loopback, link-local, and private network addresses are not allowed by default',
      };
    }
    return { kind: 'ip', value };
  }

  if (value.includes('/')) {
    if (!isValidCidr(value)) {
      return { kind: 'cidr', value, error: 'Invalid CIDR notation' };
    }
    const [ip] = value.split('/');
    if (isDisallowedIP(ip)) {
      return {
        kind: 'cidr',
        value,
        error:
          'Loopback, link-local, and private network ranges are not allowed by default',
      };
    }
    return { kind: 'cidr', value };
  }

  if (!isValidDomain(value)) {
    return { kind: 'domain', value, error: 'Invalid domain name' };
  }
  if (value === 'localhost') {
    return { kind: 'domain', value, error: 'localhost is not allowed' };
  }
  return { kind: 'domain', value };
}

/**
 * SSRF guard used right before a scanner actually connects to a resolved
 * hostname/IP. Domains are validated at registration time, but DNS can
 * change afterwards (DNS rebinding), so every scanner step re-resolves and
 * re-checks immediately before dispatching network requests.
 */
export async function assertHostResolvesInScope(hostname: string): Promise<ScopeCheckResult> {
  if (isIP(hostname)) {
    if (isDisallowedIP(hostname)) {
      return { allowed: false, reason: `IP ${hostname} is out of allowed scope` };
    }
    return { allowed: true };
  }
  try {
    const records = await dns.promises.resolve(hostname, 'A').catch(() => []);
    const records6 = await dns.promises
      .resolve(hostname, 'AAAA')
      .catch(() => []);
    const all = [...records, ...records6];
    if (all.length === 0) {
      return { allowed: false, reason: `Could not resolve ${hostname}` };
    }
    const blocked = all.filter((ip) => isDisallowedIP(ip));
    if (blocked.length > 0) {
      return {
        allowed: false,
        reason: `${hostname} resolves to disallowed address ${blocked[0]}`,
      };
    }
    return { allowed: true };
  } catch (err) {
    return { allowed: false, reason: `DNS resolution error: ${(err as Error).message}` };
  }
}
