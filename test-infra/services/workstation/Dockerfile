FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

ENV HOME=/root

RUN sed -i \
      -e 's|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/20250715T000000Z|g' \
      -e 's|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/20250715T000000Z|g' \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*

# The production identity policy intentionally makes every authoritative fact
# artifact-local when a collection point is weak. This disposable workstation
# exercises Config -> MCP -> service-collection joins, so give the fixture
# its own deterministic OS identity instead of borrowing identity from the host.
RUN printf '%s\n' '9f4c0ee2a24d4e11aee29e53b8118a37' >/etc/machine-id

# Use the same exact official MCP reference package as the HTTP and SSE
# targets. Config fixtures therefore launch a real stdio server, not printf or
# another collector-shaped stand-in.
WORKDIR /opt/mcp-everything
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts=false \
    && npm cache clean --force
RUN ln -s /opt/mcp-everything/node_modules/.bin/mcp-server-everything \
      /usr/local/bin/mcp-server-everything

COPY bin/agenthound /usr/local/bin/agenthound
COPY bin/agenthound-server /usr/local/bin/agenthound-server
COPY home/ /opt/agenthound-workstation/home/
COPY entrypoint.sh /usr/local/bin/workstation-entrypoint

RUN chmod 0755 /usr/local/bin/agenthound /usr/local/bin/agenthound-server /usr/local/bin/workstation-entrypoint \
    && cp -a /opt/agenthound-workstation/home/. /root/

WORKDIR /root/projects/example

ENTRYPOINT ["/usr/local/bin/workstation-entrypoint"]
CMD ["sleep", "infinity"]
