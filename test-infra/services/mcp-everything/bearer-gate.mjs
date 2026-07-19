import http from "node:http";

const listenPort = Number.parseInt(process.env.LISTEN_PORT ?? "3003", 10);
const upstream = new URL(process.env.UPSTREAM_URL ?? "http://mcp-streamable:3001");
const expectedBearerToken = process.env.EXPECTED_BEARER_TOKEN ?? "";
const expectedProofHeader = process.env.EXPECTED_PROOF_HEADER ?? "";
const expectedAuthorization = `Bearer ${expectedBearerToken}`;

if (
  !Number.isSafeInteger(listenPort) ||
  listenPort < 1 ||
  listenPort > 65535 ||
  upstream.protocol !== "http:" ||
  upstream.username !== "" ||
  upstream.password !== "" ||
  upstream.search !== "" ||
  upstream.hash !== "" ||
  expectedBearerToken === "" ||
  expectedProofHeader === ""
) {
  throw new Error("bearer gate configuration is invalid");
}

const server = http.createServer((request, response) => {
  const requestURL = new URL(request.url ?? "/", "http://bearer-gate.invalid");
  if (requestURL.pathname === "/healthz") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("ok\n");
    return;
  }

  if (
    request.headers.authorization !== expectedAuthorization ||
    request.headers["x-agenthound-secret"] !== expectedProofHeader
  ) {
    response.writeHead(401, { "content-type": "text/plain" });
    response.end("required MCP credential headers were not observed\n");
    return;
  }

  const headers = { ...request.headers, host: upstream.host };
  const proxyRequest = http.request(
    {
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port,
      method: request.method,
      path: `${requestURL.pathname}${requestURL.search}`,
      headers,
    },
    (proxyResponse) => {
      response.writeHead(proxyResponse.statusCode ?? 502, proxyResponse.headers);
      response.flushHeaders();
      proxyResponse.pipe(response);
    },
  );

  proxyRequest.on("error", () => {
    if (!response.headersSent) {
      response.writeHead(502, { "content-type": "text/plain" });
    }
    response.end("MCP upstream unavailable\n");
  });
  request.pipe(proxyRequest);
});

server.listen(listenPort, "0.0.0.0", () => {
  process.stdout.write(`bearer gate listening on port ${listenPort}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
