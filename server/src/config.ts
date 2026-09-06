import * as dotenv from 'dotenv';
dotenv.config();

function required(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v;
}

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '4000', 10),
  jwtSecret: required('JWT_SECRET', 'dev-insecure-secret-change-me'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '12h',
  // Prefer discrete PG* variables so no single file ever needs to contain a
  // combined connection string with an embedded password. DATABASE_URL is
  // still supported for deployments that prefer it.
  database: process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.PGHOST || 'localhost',
        port: parseInt(process.env.PGPORT || '5432', 10),
        user: process.env.PGUSER || 'recon',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'recon',
      },
  redisUrl: required('REDIS_URL', 'redis://localhost:6379'),
  evidenceDir: process.env.EVIDENCE_DIR || './data/evidence',
  // Safety / scope controls
  allowLoopbackTargets:
    (process.env.ALLOW_LOOPBACK_TARGETS || 'false').toLowerCase() === 'true',
  allowPrivateTargets:
    (process.env.ALLOW_PRIVATE_TARGETS || 'false').toLowerCase() === 'true',
  enableHighRiskTemplates:
    (process.env.ENABLE_HIGH_RISK_TEMPLATES || 'false').toLowerCase() ===
    'true',
  // Per-scanner tunables
  scanner: {
    defaultTimeoutSec: parseInt(
      process.env.SCANNER_DEFAULT_TIMEOUT_SEC || '120',
      10
    ),
    maxConcurrentJobsPerScan: parseInt(
      process.env.SCANNER_MAX_CONCURRENCY || '3',
      10
    ),
    maxRetries: parseInt(process.env.SCANNER_MAX_RETRIES || '1', 10),
    portScanTopPorts: process.env.NAABU_TOP_PORTS || '100',
    ffufWordlist:
      process.env.FFUF_WORDLIST || '/opt/wordlists/common-small.txt',
    ffufRateLimit: parseInt(process.env.FFUF_RATE_LIMIT || '20', 10),
    nucleiRateLimit: parseInt(process.env.NUCLEI_RATE_LIMIT || '50', 10),
    nucleiSeverities:
      process.env.NUCLEI_SEVERITIES || 'info,low,medium,high,critical',
    nucleiTemplatesDir:
      process.env.NUCLEI_TEMPLATES_DIR || '/opt/nuclei-templates',
    nucleiExcludeTags:
      process.env.NUCLEI_EXCLUDE_TAGS ||
      'dos,fuzz,intrusive,brute-force,rce-exploit',
  },
  binDir: process.env.SCANNER_BIN_DIR || '',
};
