import http from "node:http";

const listenPort = Number.parseInt(process.env.LISTEN_PORT ?? "3002", 10);
const upstream = new URL(process.env.UPSTREAM_URL ?? "http://mcp-streamable:3001");
const expectedUser = process.env.EXPECTED_BASIC_USER ?? "";
const expectedPassword = process.env.EXPECTED_BASIC_PASSWORD ?? "";
const expectedQuery = process.env.EXPECTED_QUERY_VALUE ?? "";
const expectedAuthorization = `Basic ${Buffer.from(`${expectedUser}:${expectedPassword}`).toString("base64")}`;

if (
  !Number.isSafeInteger(listenPort) ||
  listenPort < 1 ||
  listenPort > 65535 ||
  upstream.protocol !== "http:" ||
  upstream.username !== "" ||
  upstream.password !== "" ||
  upstream.search !== "" ||
  upstream.hash !== "" ||
  expectedUser === "" ||
  expectedPassword === "" ||
  expectedQuery === ""
) {
  throw new Error("credential gate configuration is invalid");
}

const server = http.createServer((request, response) => {
  const requestURL = new URL(request.url ?? "/", "http://credential-gate.invalid");
  if (requestURL.pathname === "/healthz") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("ok\n");
    return;
  }

  const queryValues = requestURL.searchParams.getAll("api_key");
  if (
    request.headers.authorization !== expectedAuthorization ||
    queryValues.length !== 1 ||
    queryValues[0] !== expectedQuery
  ) {
    response.writeHead(401, { "content-type": "text/plain" });
    response.end("required MCP credential path was not observed\n");
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
      // A standalone MCP SSE stream may not emit an initial body chunk. Flush
      // the upstream headers immediately so clients can finish establishing
      // the stream instead of waiting indefinitely for the first event.
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
  process.stdout.write(`credential gate listening on port ${listenPort}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
