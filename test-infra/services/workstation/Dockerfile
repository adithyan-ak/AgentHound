FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

ENV HOME=/root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        curl \
        jq \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Use the same exact official MCP reference package as the HTTP and SSE
# targets. Config fixtures therefore launch a real stdio server, not printf or
# another collector-shaped stand-in.
RUN npm install --global --omit=dev --ignore-scripts=false \
      @modelcontextprotocol/server-everything@2026.7.4 \
    && npm cache clean --force

COPY bin/agenthound /usr/local/bin/agenthound
COPY home/ /opt/agenthound-workstation/home/
COPY entrypoint.sh /usr/local/bin/workstation-entrypoint

RUN chmod 0755 /usr/local/bin/agenthound /usr/local/bin/workstation-entrypoint \
    && cp -a /opt/agenthound-workstation/home/. /root/ \
    && mkdir -p /root/.agenthound \
    && touch \
        /root/.agenthound/loot-acknowledged \
        /root/.agenthound/poison-acknowledged \
        /root/.agenthound/extract-acknowledged \
        /root/.agenthound/campaign-acknowledged

WORKDIR /root/projects/example

ENTRYPOINT ["/usr/local/bin/workstation-entrypoint"]
CMD ["sleep", "infinity"]
