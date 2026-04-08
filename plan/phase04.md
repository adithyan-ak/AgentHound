# Phase 4: Frontend

**Timeline:** Weeks 8–10
**Goal:** Usable web UI with interactive graph visualization (Sigma.js), Pathfinder, Dashboard, Entity Inspector, Scan Manager, and pre-built query library — embedded in the Go binary.

**Depends on:** Phase 1 (API server), Phase 2 (collectors providing data), Phase 3 (pathfinding API, findings, risk scores)

---

## 1. Tech Stack

| Component | Package | Version | Purpose |
|-----------|---------|---------|---------|
| Framework | React | 18+ | SPA framework |
| Language | TypeScript | 5.x | Type safety |
| Build tool | Vite | 6.x | Fast builds, HMR |
| Graph rendering | sigma | **3.0.2** | WebGL graph visualization (v3 is current) |
| Graph algorithms | graphology | **0.26.0** | Client-side graph model |
| React bindings | @react-sigma/core | **5.0.6** | React integration for Sigma.js v3 |
| Layout | graphology-layout-forceatlas2 | **0.10.1** | Force-directed layout |
| UI components | shadcn/ui | latest | Tailwind-based components |
| CSS | Tailwind CSS | 3.x | Utility-first styling |
| State management | Zustand | 5.x | Lightweight global state |
| API client | @tanstack/react-query | 5.x | Data fetching, caching |
| HTTP client | ky | 1.x | Lightweight fetch wrapper |
| Charts | Recharts | 2.x | Dashboard charts |
| Icons | lucide-react | latest | Icon set |
| Router | react-router-dom | 7.x | Client-side routing |

**Reference:** BloodHound CE uses the same Sigma.js + graphology stack.

---

## 2. Project Structure

```
ui/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts
├── postcss.config.js
├── src/
│   ├── main.tsx                    # React entry point
│   ├── App.tsx                     # Router + layout
│   ├── api/
│   │   ├── client.ts              # API base client (ky instance)
│   │   ├── graph.ts               # Graph API calls
│   │   ├── analysis.ts            # Analysis API calls
│   │   ├── scans.ts               # Scan management API calls
│   │   └── types.ts               # Shared API types
│   ├── store/
│   │   ├── graph.ts               # Graph state (selected nodes, filters)
│   │   ├── search.ts              # Search state
│   │   └── ui.ts                  # UI state (sidebar open, active view)
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppLayout.tsx       # Main layout with nav + sidebar
│   │   │   ├── Sidebar.tsx         # Right sidebar (Entity Inspector)
│   │   │   └── NavBar.tsx          # Top navigation
│   │   ├── graph/
│   │   │   ├── GraphExplorer.tsx   # Main graph view (Sigma.js container)
│   │   │   ├── GraphControls.tsx   # Zoom, layout, filter toggles
│   │   │   ├── GraphSearch.tsx     # Type-ahead node search
│   │   │   ├── GraphFilters.tsx    # Filter by node type, risk level
│   │   │   ├── GraphLegend.tsx     # Color/shape legend
│   │   │   ├── NodeRenderer.tsx    # Custom Sigma.js node program
│   │   │   └── EdgeRenderer.tsx    # Custom edge rendering
│   │   ├── pathfinder/
│   │   │   ├── Pathfinder.tsx      # Pathfinder view
│   │   │   ├── PathSelector.tsx    # Source/target node selectors
│   │   │   ├── PathResults.tsx     # Path results list
│   │   │   └── PathHighlight.tsx   # Highlight path on graph
│   │   ├── dashboard/
│   │   │   ├── Dashboard.tsx       # Dashboard view
│   │   │   ├── StatCards.tsx       # Node count cards
│   │   │   ├── RiskChart.tsx       # Risk distribution chart
│   │   │   ├── AuthCoverage.tsx    # Auth coverage pie chart
│   │   │   ├── TopFindings.tsx     # Critical findings list
│   │   │   └── RecentScans.tsx     # Scan history table
│   │   ├── inspector/
│   │   │   ├── EntityInspector.tsx # Right sidebar entity details
│   │   │   ├── NodeProperties.tsx  # Property key-value list
│   │   │   ├── NodeConnections.tsx # Connected edges grouped by type
│   │   │   ├── RiskBreakdown.tsx   # Risk score component breakdown
│   │   │   └── NodeFindings.tsx    # Findings associated with this node
│   │   ├── scans/
│   │   │   ├── ScanManager.tsx     # Scan management view
│   │   │   ├── NewScan.tsx         # Trigger new scan form
│   │   │   └── ScanHistory.tsx     # Scan history table
│   │   ├── queries/
│   │   │   ├── QueryLibrary.tsx    # Pre-built query browser
│   │   │   └── QueryResult.tsx     # Query result display
│   │   └── ui/                     # shadcn/ui components
│   │       ├── button.tsx
│   │       ├── card.tsx
│   │       ├── input.tsx
│   │       ├── select.tsx
│   │       ├── table.tsx
│   │       ├── badge.tsx
│   │       ├── tabs.tsx
│   │       ├── dialog.tsx
│   │       └── ...
│   ├── hooks/
│   │   ├── useGraph.ts            # Graph data fetching and management
│   │   ├── usePathfinding.ts      # Pathfinding API calls
│   │   ├── useNodeSearch.ts       # Type-ahead search logic
│   │   └── useGraphEvents.ts      # Sigma.js event handlers
│   ├── lib/
│   │   ├── graph-builder.ts       # Convert API response to graphology graph
│   │   ├── node-styles.ts         # Node color, size, shape by type
│   │   ├── edge-styles.ts         # Edge color, thickness, style by type
│   │   ├── layout.ts              # ForceAtlas2 configuration
│   │   └── utils.ts               # General utilities
│   └── styles/
│       └── globals.css            # Tailwind imports + custom styles
```

---

## 3. Core Views — Detailed Implementation

### 3.1 Dashboard (`/`)

Landing page. At-a-glance security posture.

**Data sources:**
- `GET /api/v1/graph/stats` → node/edge counts by kind
- `GET /api/v1/analysis/findings?severity=critical&limit=10` → top findings
- `GET /api/v1/scans?limit=5` → recent scans

**Components:**

| Component | Data | Visual |
|-----------|------|--------|
| `StatCards` | Node counts (Agents, MCP Servers, A2A Agents, Tools, Critical Paths) | 5 metric cards in a row |
| `RiskChart` | Risk score distribution across all nodes | Recharts bar chart |
| `AuthCoverage` | Auth method counts (None/API Key/OAuth/mTLS) | Recharts pie chart |
| `TopFindings` | Top 10 findings by severity | List with severity badges |
| `RecentScans` | Last 5 scans with status | Table |

### 3.2 Graph Explorer (`/graph`)

The primary view. Interactive graph visualization.

**Implementation with @react-sigma/core:**

```tsx
import { SigmaContainer, useRegisterEvents, useSetSettings, useLoadGraph } from "@react-sigma/core";
import { MultiDirectedGraph } from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";

function GraphExplorer() {
  return (
    <div className="flex h-full">
      {/* Sigma.js container — pass Graph constructor, NOT an instance.
          Passing an instance causes Sigma to be destroyed and recreated
          on every parent re-render (per @react-sigma/core docs). */}
      <div className="flex-1 relative">
        <SigmaContainer
          graph={MultiDirectedGraph}
          settings={{
            defaultNodeColor: "#999",
            defaultEdgeColor: "#ccc",
            labelRenderedSizeThreshold: 12,
            renderEdgeLabels: true,
            enableEdgeEvents: true,
          }}
        >
          <GraphDataLoader />
          <GraphEvents />
          <GraphControls />
          <GraphSearch />
          <GraphFilters />
          <GraphLegend />
        </SigmaContainer>
      </div>

      {/* Entity Inspector sidebar */}
      <EntityInspector />
    </div>
  );
}

// Child component that loads graph data using useLoadGraph() hook
function GraphDataLoader() {
  const loadGraph = useLoadGraph();
  const { data } = useGraphData();

  useEffect(() => {
    if (data) {
      loadGraph(data);
    }
  }, [data, loadGraph]);

  return null;
}
```

**Graph building (`lib/graph-builder.ts`):**

```typescript
function buildGraph(apiNodes: APINode[], apiEdges: APIEdge[]): MultiDirectedGraph {
  const graph = new MultiDirectedGraph();

  for (const node of apiNodes) {
    const style = getNodeStyle(node.kind);
    graph.addNode(node.id, {
      label: node.properties.name || node.properties.uri || node.id,
      x: Math.random(),
      y: Math.random(),
      size: getNodeSize(node),
      color: style.color,
      type: style.shape,
      // Store full data for inspector
      ...node.properties,
      _kind: node.kind,
      _riskScore: node.properties.risk_score || 0,
    });
  }

  for (const edge of apiEdges) {
    graph.addEdge(edge.source, edge.target, {
      label: edge.kind,
      color: getEdgeColor(edge.kind),
      size: getEdgeSize(edge),
      type: getEdgeType(edge.kind), // "arrow", "dashed", etc.
      _kind: edge.kind,
    });
  }

  return graph;
}
```

**Node styling (`lib/node-styles.ts`):**

| Node Kind | Color | Shape | Size Basis |
|-----------|-------|-------|-----------|
| AgentInstance | `#4A90D9` (blue) | circle | risk_score |
| MCPServer | `#50C878` (green) | circle | tool count |
| MCPTool | `#F5A623` (orange) | circle | capability risk |
| MCPResource | `#D0021B` (red) | circle | sensitivity |
| A2AAgent | `#7B68EE` (purple) | circle | skill count |
| A2ASkill | `#9B59B6` (light purple) | circle | fixed |
| Identity | `#8E8E93` (gray) | circle | fixed |
| Credential | `#FF6B6B` (warning red) | circle | exposure risk |
| ConfigFile | `#95A5A6` (silver) | circle | server count |
| Host | `#2C3E50` (dark) | circle | fixed |

**Edge styling (`lib/edge-styles.ts`):**

| Edge Kind | Color | Style |
|-----------|-------|-------|
| TRUSTS_SERVER | `#4A90D9` | solid arrow |
| PROVIDES_TOOL | `#50C878` | solid arrow |
| HAS_ACCESS_TO | `#F5A623` | solid arrow |
| DELEGATES_TO | `#7B68EE` | solid arrow |
| CAN_REACH | `#D0021B` | dashed arrow |
| CAN_EXFILTRATE_VIA | `#FF0000` | thick dashed arrow |
| SHADOWS | `#FF6B6B` | dotted arrow |
| POISONED_DESCRIPTION | `#FF0000` | self-loop, thick |

**Interactions:**

| Action | Behavior |
|--------|----------|
| Click node | Open Entity Inspector in sidebar |
| Hover node | Highlight node + immediate neighbors, dim rest |
| Right-click node | Context menu: Find paths from/to here, expand neighbors |
| Search | Type-ahead filter, zoom to matching node |
| Filter toggles | Show/hide node types, filter by risk level |
| Scroll | Zoom in/out |
| Drag | Pan canvas |

**Layout:**
- Initial: ForceAtlas2 for 2 seconds, then freeze
- Settings: `gravity: 1, scalingRatio: 2, strongGravityMode: true`
- Provide "Re-layout" button to rerun

### 3.3 Pathfinder (`/pathfinder`)

Dedicated attack path discovery.

**Components:**
- `PathSelector`: Two dropdowns (source node, target node) with type filters
- Algorithm toggle: Shortest / All Shortest / Weighted (Dijkstra)
- Max hops slider (1–10, default 6)
- Results list with path details
- "View in Graph" button — switches to Graph Explorer with path highlighted

**Path highlight on graph:**
```typescript
function highlightPath(graph: Graph, pathNodeIds: string[], pathEdgeIds: string[]) {
  const pathNodeSet = new Set(pathNodeIds);
  const pathEdgeSet = new Set(pathEdgeIds);

  graph.forEachNode((node) => {
    graph.setNodeAttribute(node, "color",
      pathNodeSet.has(node) ? getNodeStyle(graph.getNodeAttribute(node, "_kind")).color : "#333"
    );
    graph.setNodeAttribute(node, "size",
      pathNodeSet.has(node) ? graph.getNodeAttribute(node, "size") * 1.5 : graph.getNodeAttribute(node, "size") * 0.5
    );
  });

  // Use actual path edge IDs instead of checking endpoint membership,
  // which would incorrectly highlight all edges between any two path nodes
  graph.forEachEdge((edge, attrs, source, target) => {
    const onPath = pathEdgeSet.has(edge);
    graph.setEdgeAttribute(edge, "color", onPath ? "#FF0000" : "#222");
    graph.setEdgeAttribute(edge, "size", onPath ? 3 : 0.5);
  });
}
```

### 3.4 Entity Inspector (Right Sidebar)

Slides in when a node is clicked. Shows:

1. **Header:** Node name, kind badge, risk score badge
2. **Properties:** Key-value table of all node properties
3. **Connections:** Grouped by edge type, expandable lists
4. **Risk Breakdown:** Component scores (auth, blast radius, etc.)
5. **Findings:** Security findings related to this node
6. **Actions:** "View in Graph", "Find paths from/to", "Raw JSON"

### 3.5 Scan Manager (`/scans`)

- "New Scan" button → dialog with scan type selection (MCP/A2A/Config/Full)
- Scan history table: timestamp, type, status, node/edge counts
- Active scan progress (polls API)

**Note:** In MVP, scans are triggered via CLI. The UI calls `POST /api/v1/scans` which queues a scan — the API server runs the collector as a subprocess.

### 3.6 Pre-Built Query Library (`/queries`)

Card-based grid of 17 pre-built queries from Phase 3:

| Category | Queries |
|----------|---------|
| Critical Paths | 5 queries |
| Vulnerabilities | 5 queries |
| Supply Chain | 4 queries |
| Chokepoints | 2 queries |
| Combined | 1 query |

Click a query → runs it → shows results (table or graph view).

---

## 4. API Integration

### 4.1 API Client (`api/client.ts`)

```typescript
import ky from "ky";

export const api = ky.create({
  prefixUrl: "/api/v1",
  headers: { "Content-Type": "application/json" },
});
```

### 4.2 React Query Hooks

```typescript
// hooks/useGraph.ts
export function useGraphData() {
  return useQuery({
    queryKey: ["graph", "full"],
    queryFn: async () => {
      const nodes = await api.get("graph/nodes?limit=10000").json<APINode[]>();
      const edges = await api.get("graph/edges?limit=50000").json<APIEdge[]>();
      return buildGraph(nodes, edges);  // Returns a Graph instance for useLoadGraph()
    },
    staleTime: 30_000, // 30s — re-renders from stale/refocus won't recreate Sigma
    // because graph instance is passed via useLoadGraph(), not as a SigmaContainer prop
  });
}

// hooks/usePathfinding.ts
export function useShortestPath() {
  return useMutation({
    mutationFn: (req: ShortestPathRequest) =>
      api.post("analysis/shortest-path", { json: req }).json<PathResponse>(),
  });
}
```

---

## 5. Embedding in Go Binary

### 5.1 Build Process

```bash
# In Makefile
ui-build:
	cd ui && pnpm install && pnpm build
	# Copy into internal/api/ so go:embed can find it (Go forbids .. in embed paths)
	rm -rf internal/api/ui/dist
	mkdir -p internal/api/ui
	cp -r ui/dist internal/api/ui/dist

build: ui-build
	go build -o bin/agenthound ./cmd/agenthound
```

### 5.2 Go Embed

The Makefile copies the Vite build output into `internal/api/ui/dist/` before `go build`,
because Go's `//go:embed` forbids `..` path elements — patterns must resolve within the
package directory.

```makefile
# In Makefile — add copy step
ui-build:
	cd ui && pnpm install && pnpm build
	rm -rf internal/api/ui/dist
	mkdir -p internal/api/ui
	cp -r ui/dist internal/api/ui/dist
```

```go
// internal/api/server.go
import "embed"

//go:embed all:ui/dist
var uiFS embed.FS

func (s *Server) setupRoutes() {
    // API routes
    s.router.Route("/api/v1", func(r chi.Router) { /* ... */ })

    // Serve embedded React SPA
    uiContent, _ := fs.Sub(uiFS, "ui/dist")
    fileServer := http.FileServer(http.FS(uiContent))

    // Serve static files
    s.router.Handle("/assets/*", fileServer)

    // SPA fallback: serve index.html for all non-API, non-asset routes
    s.router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
        // Try to serve the file; if not found, serve index.html
        f, err := uiContent.Open(r.URL.Path[1:])
        if err != nil {
            // Serve index.html for SPA routing
            indexHTML, _ := uiContent.Open("index.html")
            defer indexHTML.Close()
            w.Header().Set("Content-Type", "text/html")
            io.Copy(w, indexHTML)
            return
        }
        f.Close()
        fileServer.ServeHTTP(w, r)
    })
}
```

### 5.3 Vite Config for Embedding

```typescript
// vite.config.ts
export default defineConfig({
  base: "/",      // Serve from root
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",  // Dev proxy to Go backend
    },
  },
});
```

During development: `pnpm dev` (Vite dev server on :5173, proxies API to :8080)
In production: Built SPA embedded in Go binary, served from :8080

---

## 6. Performance Targets

| Metric | Target | How to Achieve |
|--------|--------|----------------|
| Initial render < 1K nodes | < 500ms | Default Sigma.js WebGL is fast at this scale |
| Initial render 1K-10K nodes | < 2s | Disable edge labels, reduce node label threshold |
| Initial render 10K-100K nodes | < 5s | Disable all labels, use simple circle nodes |
| Interaction latency (hover, click) | < 50ms | Sigma.js WebGL handles this natively |
| Path highlight animation | < 200ms | Direct attribute manipulation, no re-render |
| Search results | < 100ms | Client-side search on graphology graph |

**Optimizations for large graphs:**
- Paginate node/edge loading from API
- Use graphology's `forEachNode` (O(n)) not `nodes()` (creates array)
- Disable ForceAtlas2 for > 5K nodes (use random initial layout)
- Use Sigma.js WebGL2 renderer for > 10K nodes
- Aggregate small nodes (e.g., collapse tools under server)

---

## 7. Tests

### Component Tests (Vitest + React Testing Library)

| Test | What It Validates |
|------|-------------------|
| `Dashboard.test.tsx` | Renders stat cards with correct counts from mock API |
| `GraphExplorer.test.tsx` | Sigma.js container mounts, nodes rendered |
| `Pathfinder.test.tsx` | Form submission calls API, results displayed |
| `EntityInspector.test.tsx` | Properties table populated from node data |
| `QueryLibrary.test.tsx` | All 17 queries rendered as cards |

### E2E Tests (Playwright)

| Test | Steps | Verification |
|------|-------|-------------|
| `dashboard-loads` | Navigate to `/` | Stat cards visible, no errors |
| `graph-explorer-renders` | Navigate to `/graph` | Sigma.js canvas rendered, nodes visible |
| `click-node-inspector` | Click a node on graph | Inspector sidebar opens with node properties |
| `pathfinder-shortest-path` | Select source/target, click Find | Results list appears with at least 1 path |
| `path-highlight` | Click "View in Graph" on path result | Graph view shows highlighted path |
| `search-node` | Type node name in search | Matching node highlighted/zoomed |
| `filter-by-type` | Toggle off MCPTool filter | Tool nodes hidden from graph |
| `scan-manager` | Navigate to `/scans` | Scan history table visible |

---

## 8. Success Metrics / Exit Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | User opens `http://localhost:8080`, sees Dashboard with correct stats | E2E test |
| 2 | Graph Explorer renders all nodes from seeded data | Sigma.js canvas shows nodes |
| 3 | Clicking a node opens Entity Inspector with correct properties | E2E test |
| 4 | Pathfinder: select source/target → see attack paths highlighted | E2E test |
| 5 | Pre-built queries return results and display correctly | All 17 queries functional |
| 6 | Graph renders 1K nodes in < 2 seconds | Performance benchmark |
| 7 | Search finds nodes by name in < 100ms | Client-side search test |
| 8 | React app builds and embeds in Go binary | `agenthound serve` serves UI |
| 9 | Dev proxy (Vite → Go) works for development | `pnpm dev` + `go run` work together |
| 10 | All Playwright E2E tests pass | CI pipeline |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Sigma.js v3 API complexity | Medium | Follow @react-sigma/core v5 examples closely. BloodHound CE's Sigma.js usage is a reference. |
| ForceAtlas2 layout unstable for small graphs | Low | Tune gravity/scaling params. Provide manual drag-to-reposition. |
| Graph rendering performance with many edges | Medium | Hide edges at low zoom. Cull off-screen nodes. |
| SPA routing conflicts with Go server | Low | Go serves `index.html` for all non-API routes (SPA fallback). |
| go:embed increases binary size | Low | Vite production build with minification + gzip. Expect ~2-5MB total. |

---

## 10. External References

| Resource | URL | Relevance |
|----------|-----|-----------|
| Sigma.js docs | https://www.sigmajs.org/ | Graph rendering |
| @react-sigma/core | https://sim51.github.io/react-sigma/ | React bindings |
| graphology | https://graphology.github.io/ | Graph data model |
| graphology-layout-forceatlas2 | https://graphology.github.io/standard-library/layout-forceatlas2 | Layout |
| shadcn/ui | https://ui.shadcn.com/ | UI components |
| Tailwind CSS | https://tailwindcss.com/ | CSS framework |
| Recharts | https://recharts.org/ | Charts |
| TanStack Query | https://tanstack.com/query/ | Data fetching |
| Zustand | https://zustand.docs.pmnd.rs/ | State management |
| BloodHound CE UI | https://github.com/SpecterOps/BloodHound/tree/main/packages/javascript | Reference implementation |
