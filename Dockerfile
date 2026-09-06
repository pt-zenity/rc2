# syntax=docker/dockerfile:1
#
# Recon Suite - API + Worker image.
#
# Multi-stage build:
#   1. gobuild    - compiles pinned versions of the open-source scanner
#                   tools used by the reconnaissance pipeline.
#   2. nodebuild  - installs npm dependencies and compiles the TypeScript
#                   server (API + worker share the same codebase/image).
#   3. templates  - shallow-clones nuclei-templates at a pinned commit so
#                   vulnerability scans use a reproducible template set.
#   4. final      - minimal runtime image with the compiled binaries,
#                   compiled JS, and templates copied in.
#
# All scanner tool versions and the nuclei-templates commit are pinned so
# that builds are reproducible.

FROM golang:1.24-bookworm AS gobuild
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV CGO_ENABLED=1 GOBIN=/out
RUN mkdir -p /out
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.1.6
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1
RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.0.5
RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.4
RUN go install github.com/ffuf/ffuf/v2@v2.1.0
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.2

FROM alpine/git:2.45.2 AS templates
# Pinned nuclei-templates commit for reproducible vulnerability scans.
ARG NUCLEI_TEMPLATES_REF=c6e3cf0d71167e3bbe9d2c168fcc6d54e3220256
RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /templates \
    && cd /templates && git checkout ${NUCLEI_TEMPLATES_REF} \
    && rm -rf /templates/.git

FROM node:20-bookworm-slim AS nodebuild
WORKDIR /app
COPY server/package.json server/package-lock.json ./
RUN npm ci
COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build

FROM node:20-bookworm-slim AS final
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 recon
WORKDIR /app

COPY --from=gobuild /out/ /usr/local/bin/
COPY --from=templates /templates /opt/nuclei-templates

COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev

COPY --from=nodebuild /app/dist ./dist
COPY server/wordlists ./wordlists

ENV NODE_ENV=production \
    SCANNER_BIN_DIR=/usr/local/bin \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    WORDLIST_DIR=/app/wordlists \
    EVIDENCE_DIR=/data/evidence

RUN mkdir -p /data/evidence && chown -R recon:recon /data /app
USER recon

EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://127.0.0.1:4000/healthz || exit 1

CMD ["node", "dist/api/server.js"]
