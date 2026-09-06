# Recon Suite — Web Dashboard

React + TypeScript + Vite single-page application for the Web Application
Reconnaissance Suite. Provides authentication, target management, scan
launch/monitoring, and the full results dashboard (subdomains, DNS, IPs,
ports, live hosts, technologies, URLs, findings, scan logs, raw evidence)
with filtering, search, sorting, pagination, and CSV/JSON export.

## Development

```bash
npm install
cp .env.example .env.local   # set VITE_API_BASE_URL to the API server
npm run dev
```

## Build

```bash
npm run build
```

Outputs static assets to `dist/`, servable by any static file server or the
provided Docker image (see `Dockerfile` / `docker-compose.yml` at the repo
root).
