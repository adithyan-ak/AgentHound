import ky from "ky";

// The collector and server are auth-less. The browser hits the same origin
// (the Go binary serves both UI and API), so no Authorization header,
// CORS preflight, or 401-redirect plumbing is needed.
export const api = ky.create({
  prefixUrl: "/api/v1",
});
