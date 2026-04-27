import ky from "ky";

// Localhost-token bootstrap.
//
// The server gates mutating endpoints (/ingest, /query, /scans POST/DELETE,
// /analysis/*-path) with a Bearer token written to disk at server startup.
// The UI fetches that token from /api/v1/auth/local-token on first need
// and includes it in every subsequent mutating request. Reads stay open.
//
// We hold the in-flight Promise so concurrent first-time mutators share
// one token fetch instead of racing against the server. The token is
// stable per server process; no refresh logic is required.
let tokenPromise: Promise<string> | null = null;

async function fetchLocalToken(): Promise<string> {
  const res = await fetch("/api/v1/auth/local-token", {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(
      `failed to fetch localhost token (status ${res.status})`,
    );
  }
  const body = (await res.json()) as { token?: string };
  if (!body.token) {
    throw new Error("token missing in /auth/local-token response");
  }
  return body.token;
}

function getLocalToken(): Promise<string> {
  if (!tokenPromise) {
    tokenPromise = fetchLocalToken().catch((err) => {
      // Reset so the next attempt re-fetches; otherwise a transient
      // 502 on first load would lock the UI out for the session.
      tokenPromise = null;
      throw err;
    });
  }
  return tokenPromise;
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export const api = ky.create({
  prefixUrl: "/api/v1",
  hooks: {
    beforeRequest: [
      async (req) => {
        const method = req.method.toUpperCase();
        if (!MUTATING_METHODS.has(method)) return;
        // Bypass the bootstrap endpoint to avoid recursion.
        if (req.url.endsWith("/auth/local-token")) return;
        const token = await getLocalToken();
        req.headers.set("Authorization", `Bearer ${token}`);
      },
    ],
  },
});

// Exported for tests that need to seed or reset the cached token.
export const __test__ = {
  resetTokenCache: () => {
    tokenPromise = null;
  },
  setTokenCache: (token: string) => {
    tokenPromise = Promise.resolve(token);
  },
};
