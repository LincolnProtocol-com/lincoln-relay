# syntax=docker/dockerfile:1.7
# Code and locked tools only. Production parameters and all keystores are mounts.
ARG NODE_IMAGE=node:24.22.0-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5
ARG FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:v1.8.4@sha256:f69e1b8d1dda17d89227a4d0513b1d86f93ece430dea8d87aaea643da3607d3e
FROM ${NODE_IMAGE} AS dependencies
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
FROM ${FOUNDRY_IMAGE} AS foundry
FROM ${NODE_IMAGE} AS mainnet-runtime
ENV NODE_ENV=production HOME=/tmp/mainnet-home LINCOLN_MAINNET_SIGNING_ENABLED=0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 lincoln-mainnet \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin lincoln-mainnet \
    && install -d -o 10001 -g 10001 -m 0700 /app/.phase1-private/phase2-mainnet \
    && mkdir -p /run/config/mainnet /run/secrets /app/config /app/artifacts /app/protocol /app/vendor
WORKDIR /app
COPY --from=dependencies /build/node_modules ./node_modules
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
# The adjacent runtime.Dockerfile.dockerignore is a finite public allowlist.
COPY . .
USER 10001:10001
RUN node --input-type=module -e "await import('./docker/mainnet/start.mjs'); await import('./src/phase2-mainnet/release.mjs');" \
    && cast --version | grep -F 'Version: 1.8.4'
EXPOSE 8797
STOPSIGNAL SIGTERM
# The default command is an offline plan and cannot start a signer or listener.
CMD ["node", "/app/docker/mainnet/start.mjs", "plan"]
