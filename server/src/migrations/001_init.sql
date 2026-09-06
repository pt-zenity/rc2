-- Initial schema for Web Recon Suite
-- Data model: target -> scan -> subdomain -> ip -> port/service -> url/endpoint -> technology -> finding

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  ip_address TEXT,
  meta JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Authorized scope: every target must be explicitly created and marked authorized
-- before any scan can be queued against it (allowlist model).
CREATE TABLE IF NOT EXISTS targets (
  id SERIAL PRIMARY KEY,
  value TEXT NOT NULL UNIQUE, -- domain, IP or CIDR, normalized lowercase
  kind TEXT NOT NULL CHECK (kind IN ('domain', 'ip', 'cidr')),
  authorized BOOLEAN NOT NULL DEFAULT false,
  authorization_note TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','partial','failed','cancelled')),
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- One row per scanner tool invocation within a scan (job queue execution unit)
CREATE TABLE IF NOT EXISTS scan_jobs (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','timeout','skipped','cancelled')),
  attempt INTEGER NOT NULL DEFAULT 1,
  max_attempts INTEGER NOT NULL DEFAULT 2,
  timeout_sec INTEGER NOT NULL DEFAULT 120,
  exit_code INTEGER,
  command TEXT,
  error TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_scan ON scan_jobs(scan_id);

CREATE TABLE IF NOT EXISTS scan_logs (
  id BIGSERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scan_job_id INTEGER REFERENCES scan_jobs(id) ON DELETE CASCADE,
  level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('debug','info','warn','error')),
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id);

-- Raw scanner output stored on disk, referenced here as evidence for traceability.
CREATE TABLE IF NOT EXISTS evidence (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scan_job_id INTEGER REFERENCES scan_jobs(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('stdout','stderr','raw_output')),
  file_path TEXT NOT NULL,
  byte_size INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);

CREATE TABLE IF NOT EXISTS subdomains (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_id);

CREATE TABLE IF NOT EXISTS dns_records (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  record_type TEXT NOT NULL,
  value TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, hostname, record_type, value)
);

CREATE INDEX IF NOT EXISTS idx_dns_records_scan ON dns_records(scan_id);

CREATE TABLE IF NOT EXISTS ip_addresses (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  hostname TEXT,
  ip TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, hostname, ip)
);

CREATE INDEX IF NOT EXISTS idx_ip_addresses_scan ON ip_addresses(scan_id);

CREATE TABLE IF NOT EXISTS ports (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  service TEXT,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, ip, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);

-- Live host HTTP(S) probe result, including TLS and technology detection data.
CREATE TABLE IF NOT EXISTS http_probes (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  url TEXT NOT NULL,
  status_code INTEGER,
  title TEXT,
  webserver TEXT,
  content_length INTEGER,
  tls_json JSONB,
  tech JSONB NOT NULL DEFAULT '[]'::jsonb,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, url)
);

CREATE INDEX IF NOT EXISTS idx_http_probes_scan ON http_probes(scan_id);

CREATE TABLE IF NOT EXISTS technologies (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  http_probe_id INTEGER REFERENCES http_probes(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT,
  source_tool TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, url, name)
);

CREATE INDEX IF NOT EXISTS idx_technologies_scan ON technologies(scan_id);

CREATE TABLE IF NOT EXISTS urls (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  status_code INTEGER,
  content_length INTEGER,
  source_tool TEXT NOT NULL, -- katana | gau | ffuf
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, url, source_tool)
);

CREATE INDEX IF NOT EXISTS idx_urls_scan ON urls(scan_id);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  tool_name TEXT NOT NULL,
  template_id TEXT,
  name TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('critical','high','medium','low','info','unknown')),
  hostname TEXT,
  ip TEXT,
  matched_url TEXT,
  description TEXT,
  evidence_snippet TEXT,
  remediation TEXT,
  reference JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scan_id, tool_name, template_id, matched_url)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
