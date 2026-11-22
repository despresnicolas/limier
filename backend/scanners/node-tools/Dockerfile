# Tool image for code analysis, clones and lockfile regeneration.
# Runs as non-root with a read-only root filesystem: everything writable lives in /work or /tmp.
FROM node:22.20-alpine3.22

ARG SCC_VERSION=3.5.0
ARG KNIP_VERSION=5.64.1
ARG DEPCRUISE_VERSION=17.0.1
ARG TYPESCRIPT_VERSION=5.9.3

RUN apk add --no-cache git ca-certificates \
 && arch="$(uname -m)" \
 && case "$arch" in x86_64) scc_arch=x86_64 ;; aarch64) scc_arch=arm64 ;; *) echo "unsupported arch $arch" && exit 1 ;; esac \
 && wget -qO- "https://github.com/boyter/scc/releases/download/v${SCC_VERSION}/scc_Linux_${scc_arch}.tar.gz" | tar -xz -C /usr/local/bin scc \
 && npm install --global --ignore-scripts --no-audit --no-fund \
      "knip@${KNIP_VERSION}" "dependency-cruiser@${DEPCRUISE_VERSION}" "typescript@${TYPESCRIPT_VERSION}" \
 && corepack enable \
 && npm cache clean --force

ENV HOME=/tmp NPM_CONFIG_CACHE=/tmp/npm COREPACK_HOME=/tmp/corepack NPM_CONFIG_UPDATE_NOTIFIER=false
USER 65532:65532
WORKDIR /work
