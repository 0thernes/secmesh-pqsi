# SPDX-License-Identifier: Apache-2.0
# Multi-stage hardened production container for SecMesh-PQSI v3.0.0
# Builds native C11 Moonlab + TUN + CT-Worker binary, copies only runtime artifacts
# into a non-root (UID 65532) minimal Debian slim image.

FROM node:25-bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY native ./native
RUN make -C native all test const-time

FROM node:25-bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 secmesh \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home secmesh
WORKDIR /opt/secmesh-pqsi
COPY --from=builder /src/native/build/secmesh_core ./native/build/secmesh_core
COPY node ./node
COPY eshkol ./eshkol
COPY package.json VERSION LICENSE ./
RUN chown -R 65532:65532 /opt/secmesh-pqsi
USER 65532:65532
ENV NODE_ENV=production
EXPOSE 7777/tcp 7778/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD node node/src/secmesh-cli.mjs tun-probe >/dev/null 2>&1 || exit 1
ENTRYPOINT ["node", "node/src/secmesh-cli.mjs"]
CMD ["audit"]
