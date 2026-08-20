import http from "node:http";
import { Transform } from "node:stream";
import { StringDecoder } from "node:string_decoder";

const listenPort = Number.parseInt(process.env.LISTEN_PORT ?? "3003", 10);
const upstream = new URL(process.env.UPSTREAM_URL ?? "http://mcp-streamable:3001");
const expectedBearerToken = process.env.EXPECTED_BEARER_TOKEN ?? "";
const expectedProofHeader = process.env.EXPECTED_PROOF_HEADER ?? "";
const toolResourceHint = process.env.TOOL_RESOURCE_HINT ?? "";
const expectedAuthorization = `Bearer ${expectedBearerToken}`;

function addToolResourceHint(payload) {
  const tool = payload?.result?.tools?.find(
    (candidate) => candidate.name === "get-resource-reference",
  );
  if (tool === undefined) {
    return false;
  }
  tool.description = `${tool.description} Accesses ${toolResourceHint}.`;
  return true;
}

function rewriteResponse(body, contentType) {
  const text = body.toString("utf8");
  if (contentType.includes("application/json")) {
    const payload = JSON.parse(text);
    return addToolResourceHint(payload)
      ? Buffer.from(JSON.stringify(payload))
      : body;
  }
  return body;
}

function rewriteSSELine(line) {
  if (!line.startsWith("data:")) {
    return line;
  }
  try {
    const payload = JSON.parse(line.slice("data:".length).trimStart());
    return addToolResourceHint(payload)
      ? `data: ${JSON.stringify(payload)}`
      : line;
  } catch {
    return line;
  }
}

function sseRewriteStream() {
  let pending = "";
  const decoder = new StringDecoder("utf8");
  return new Transform({
    transform(chunk, _encoding, callback) {
      pending += decoder.write(chunk);
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      try {
        callback(
          null,
          lines.length === 0
            ? undefined
            : `${lines.map(rewriteSSELine).join("\n")}\n`,
        );
      } catch (error) {
        callback(error);
      }
    },
    flush(callback) {
      try {
        pending += decoder.end();
        callback(null, pending === "" ? undefined : rewriteSSELine(pending));
      } catch (error) {
        callback(error);
      }
    },
  });
}

if (
  !Number.isSafeInteger(listenPort) ||
  listenPort < 1 ||
  listenPort > 65535 ||
  upstream.protocol !== "http:" ||
  upstream.username !== "" ||
  upstream.password !== "" ||
  upstream.search !== "" ||
  upstream.hash !== "" ||
  expectedBearerToken === ""
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
    (expectedProofHeader !== "" &&
      request.headers["x-agenthound-secret"] !== expectedProofHeader)
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
      const contentType = String(proxyResponse.headers["content-type"] ?? "");
      if (toolResourceHint !== "" && contentType.includes("text/event-stream")) {
        const headers = { ...proxyResponse.headers };
        delete headers["content-length"];
        response.writeHead(proxyResponse.statusCode ?? 502, headers);
        response.flushHeaders();
        proxyResponse.pipe(sseRewriteStream()).pipe(response);
        return;
      }
      if (
        toolResourceHint === "" ||
        request.method !== "POST" ||
        !contentType.includes("application/json")
      ) {
        response.writeHead(proxyResponse.statusCode ?? 502, proxyResponse.headers);
        response.flushHeaders();
        proxyResponse.pipe(response);
        return;
      }

      const chunks = [];
      proxyResponse.on("data", (chunk) => chunks.push(chunk));
      proxyResponse.on("end", () => {
        const body = Buffer.concat(chunks);
        let output = body;
        try {
          output = rewriteResponse(body, contentType);
        } catch {
          // Preserve non-JSON and malformed upstream responses byte-for-byte.
        }

        const headers = { ...proxyResponse.headers };
        delete headers["content-length"];
        response.writeHead(proxyResponse.statusCode ?? 502, headers);
        response.end(output);
      });
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
