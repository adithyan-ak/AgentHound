// Central query-key factory — the cache addressing scheme (infrastructure,
// not domain logic). Every entity hook and every invalidation derives its key
// from here so the cache namespace stays consistent and discoverable. This
// replaces the 22 inline `queryKey: [...]` literals scattered across the app
// and collapses the previously-duplicated keys (4x ["findings"], 2x ["health"],
// the ["dashboard","*"] variants, and the two node-detail surfaces).

export const qk = {
  graphStats: () => ["graph", "stats"] as const,

  // Standalone node list (dashboard). The explorer pulls nodes inside its own
  // ["explorer","graph"] bundle, so this key has a single consumer.
  nodes: (kind?: string, limit?: number) =>
    ["nodes", kind ?? null, limit ?? null] as const,
  // Single node-detail cache for the Explorer drawer.
  node: (id: string) => ["node", id] as const,

  edges: () => ["edges", "all"] as const,

  // One findings cache — unifies the dashboard, findings list, node findings,
  // references, and navigation surfaces (all fetched the full set). The
  // optional includeSuppressed segment lets the findings register show
  // accepted-risk / false-positive rows under a distinct cache entry; call
  // with no argument to address the whole findings namespace for
  // invalidation.
  findings: (includeSuppressed?: boolean) =>
    includeSuppressed === undefined
      ? (["findings"] as const)
      : (["findings", includeSuppressed] as const),
  findingDetail: (id: string) => ["finding-detail", id] as const,
  // Per-fingerprint triage state — one key per finding so a triage edit
  // invalidates just that row's standalone query (the list query carries
  // triage inline and is invalidated by prefix).
  triage: (fingerprint: string) => ["triage", fingerprint] as const,

  // One scans hook, parameterized by page size: the scan manager (50) and the
  // dashboard (20) keep distinct cache entries so a write to one does not
  // disturb the other.
  scans: (limit: number) => ["scans", limit] as const,
  scan: (id: string) => ["scan", id] as const,
  scanPage: (limit: number, offset: number, revision?: string) =>
    ["scans", limit, "page", offset, revision ?? null] as const,
  latestScan: (order: "completed" | "published") =>
    ["scans", "latest", order] as const,

  rules: (filters: { collector?: string; severity?: string; tag?: string }) =>
    ["rules", filters] as const,
  ruleDetail: (id: string) => ["rule-detail", id] as const,

  prebuiltQueries: () => ["prebuilt-queries"] as const,
  // Cached result of a named pre-built query (cross-protocol / chokepoint
  // dashboard widgets). Replaces ["dashboard","cross-protocol-paths"] etc.
  prebuiltResult: (id: string) => ["prebuilt", id] as const,

  health: () => ["health"] as const,
  posture: () => ["posture"] as const,

  explorerGraph: () => ["explorer", "graph"] as const,
  blastRadius: (
    sourceId: string | null,
    direction: "out" | "in" | "both",
    maxHops: number,
  ) => ["explorer", "blast-radius", sourceId, direction, maxHops] as const,
} as const;
