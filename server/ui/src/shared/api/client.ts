import ky from "ky";

// Mutations from the embedded UI are same-origin POSTs. The browser
// automatically attaches `Origin: http://localhost:8080` (per Fetch
// spec §3.1); the server's OriginGuard middleware admits requests whose
// Origin is in the CORS allowlist. No client-side auth is required.
export const api = ky.create({ prefixUrl: "/api/v1" });
