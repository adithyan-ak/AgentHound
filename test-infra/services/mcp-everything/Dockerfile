# Official MCP reference test server, installed at an immutable npm release.
FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

WORKDIR /opt/mcp-everything
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts=false \
    && npm cache clean --force

USER node
EXPOSE 3001
ENTRYPOINT ["/opt/mcp-everything/node_modules/.bin/mcp-server-everything"]
CMD ["streamableHttp"]
