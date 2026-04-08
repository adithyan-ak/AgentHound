# Sigma.js + @react-sigma/core + Graphology Stack Research

> Researched 2026-04-07. All version numbers and API signatures verified against npm and official docs.

---

## 1. Current Versions (as of April 2026)

| Package | Version | npm |
|---|---|---|
| `sigma` | **3.0.2** | [npm](https://www.npmjs.com/package/sigma) |
| `graphology` | **0.26.0** | [npm](https://www.npmjs.com/package/graphology) |
| `@react-sigma/core` | **5.0.6** | [npm](https://www.npmjs.com/package/@react-sigma/core) |
| `@react-sigma/layout-forceatlas2` | **5.0.6** | [npm](https://www.npmjs.com/package/@react-sigma/layout-forceatlas2) |
| `graphology-layout-forceatlas2` | **0.10.1** | [npm](https://www.npmjs.com/package/graphology-layout-forceatlas2) |
| `graphology-shortest-path` | (part of graphology monorepo) | [npm](https://www.npmjs.com/package/graphology-shortest-path) |

**Peer dependency relationships:**
- `sigma` 3.x depends on `graphology` (peer)
- `@react-sigma/core` 5.x depends on `sigma` 3.x and `graphology` 0.x (peers)
- `@react-sigma/layout-forceatlas2` 5.x depends on `@react-sigma/core` 5.x (peer)

---

## 2. Project Setup: React + TypeScript + Sigma.js

### Install all packages

```bash
npm install sigma graphology @react-sigma/core @react-sigma/layout-forceatlas2 graphology-layout-forceatlas2 graphology-layout graphology-shortest-path graphology-types
```

### Typed graphology constructors

```ts
import Graph from "graphology";                          // mixed graph (default)
import { DirectedGraph, UndirectedGraph } from "graphology";
import { MultiDirectedGraph } from "graphology";         // multi-edge directed
```

### Minimal React setup

```tsx
import { useEffect } from "react";
import Graph from "graphology";
import { SigmaContainer, useLoadGraph } from "@react-sigma/core";
import "@react-sigma/core/lib/style.css";

const MyGraph = () => {
  const loadGraph = useLoadGraph();

  useEffect(() => {
    const graph = new Graph();
    graph.addNode("a", { x: 0, y: 0, size: 15, label: "Node A", color: "#FA4F40" });
    graph.addNode("b", { x: 1, y: 1, size: 10, label: "Node B", color: "#4F40FA" });
    graph.addEdge("a", "b", { size: 3, color: "#ccc" });
    loadGraph(graph);
  }, [loadGraph]);

  return null;
};

export const App = () => (
  <SigmaContainer style={{ height: "100vh", width: "100%" }}>
    <MyGraph />
  </SigmaContainer>
);
```

**Critical:** The SigmaContainer **must have a defined height**. Without it, nothing renders.

**Critical:** Import the CSS: `import "@react-sigma/core/lib/style.css";`

### Using a typed graph constructor with SigmaContainer

```tsx
import { MultiDirectedGraph } from "graphology";

<SigmaContainer graph={MultiDirectedGraph}>
  <MyGraph />
</SigmaContainer>
```

When you pass a constructor (not an instance), SigmaContainer creates the internal graph for you. If you pass an instance directly, Sigma will be killed and recreated on every parent render -- avoid this for heavy graphs.

---

## 3. Graphology API: Creating and Manipulating Graphs

### Instantiation

```ts
import Graph from "graphology";

// Default: mixed, self-loops allowed, no multi-edges
const graph = new Graph();

// Options
const graph = new Graph({
  type: "directed",       // "directed" | "undirected" | "mixed"
  multi: false,           // allow multiple edges between same pair
  allowSelfLoops: true,
});
```

**Typed constructors:** `DirectedGraph`, `UndirectedGraph`, `MultiGraph`, `MultiDirectedGraph`, `MultiUndirectedGraph`.

### Node mutations

```ts
// addNode(key, attributes?) -> key
// Throws if node already exists
graph.addNode("john", { age: 24, eyes: "blue", x: 0, y: 0, size: 10, color: "#e22653", label: "John" });

// mergeNode(key, attributes?) -> [key, wasAdded]
// Adds if not exists; merges attributes if exists
const [key, wasAdded] = graph.mergeNode("john", { eyes: "green" });

// updateNode(key, updater) -> [key, wasAdded]
// Adds if not exists; calls updater(currentAttrs) if exists
graph.updateNode("john", attr => ({ ...attr, visits: (attr.visits || 0) + 1 }));

// dropNode(key) -- removes node and all attached edges
graph.dropNode("john");
```

### Edge mutations

```ts
// addEdge(source, target, attributes?) -> auto-generated key
const edgeKey = graph.addEdge("john", "martha", { weight: 1, color: "#ccc", size: 2 });

// addEdgeWithKey(key, source, target, attributes?) -> key
graph.addEdgeWithKey("john->martha", "john", "martha", { type: "KNOWS", weight: 1 });

// mergeEdge(source, target, attributes?) -> [key, edgeAdded, sourceAdded, targetAdded]
// Creates missing nodes automatically!
const [key, edgeAdded, srcAdded, tgtAdded] = graph.mergeEdge("john", "martha", { weight: 2 });

// updateEdge(source, target, updater) -> [key, edgeAdded, sourceAdded, targetAdded]
graph.updateEdge("john", "martha", attr => ({ ...attr, weight: (attr.weight || 0) + 1 }));

// dropEdge(key) or dropEdge(source, target)
graph.dropEdge("john", "martha");

// Directed variants: addDirectedEdge, addUndirectedEdge, etc.
```

### Attributes API

```ts
// Node attributes
graph.getNodeAttribute("john", "age");           // 24
graph.getNodeAttributes("john");                 // { age: 24, eyes: "blue", ... }
graph.setNodeAttribute("john", "age", 25);
graph.updateNodeAttribute("john", "age", v => v + 1);
graph.removeNodeAttribute("john", "age");
graph.replaceNodeAttributes("john", { x: 0, y: 0 });
graph.mergeNodeAttributes("john", { label: "John D." });

// Edge attributes (same pattern)
graph.getEdgeAttribute(edgeKey, "weight");
graph.setEdgeAttribute(edgeKey, "weight", 5);

// Batch update all nodes
graph.updateEachNodeAttributes((node, attr) => {
  return { ...attr, size: Math.sqrt(graph.degree(node)) };
});
```

### Reading / querying

```ts
graph.hasNode("john");            // boolean
graph.hasEdge("john", "martha");  // boolean
graph.order;                      // number of nodes
graph.size;                       // number of edges
graph.degree("john");             // total degree
graph.source(edgeKey);            // source node of edge
graph.target(edgeKey);            // target node of edge
graph.neighbors("john");          // string[]
graph.areNeighbors("john", "martha"); // boolean
```

### Iteration

```ts
// Arrays
graph.nodes();                    // string[] of all node keys
graph.edges();                    // string[] of all edge keys

// Functional iteration (more memory-efficient than .nodes()/.edges())
graph.forEachNode((node, attributes) => { ... });
graph.forEachEdge((edge, attributes, source, target, sourceAttributes, targetAttributes) => { ... });
graph.forEachNeighbor("john", (neighbor, attributes) => { ... });

// Map, filter, reduce, find, some, every variants all exist
graph.mapNodes((node, attr) => attr.label);
graph.filterNodes((node, attr) => attr.size > 5);
graph.findNode((node, attr) => attr.label === "John");
```

### Serialization

```ts
// Export to JSON
const data = graph.export();
// { attributes: {}, nodes: [{key, attributes}], edges: [{key, source, target, attributes}] }

// Import from JSON
graph.import(data);

// Or static construction
const graph = Graph.from(data);
```

---

## 4. ForceAtlas2 Layout Configuration

### graphology-layout-forceatlas2

**Pre-requisite:** Every node MUST have `x` and `y` attributes set BEFORE running FA2. Use `graphology-layout` to initialize:

```ts
import { random } from "graphology-layout";
random.assign(graph);  // assigns random x, y to all nodes
```

### Settings (all optional, with defaults)

| Setting | Type | Default | Description |
|---|---|---|---|
| `adjustSizes` | boolean | `false` | Account for node sizes in repulsion |
| `barnesHutOptimize` | boolean | `false` | Use Barnes-Hut approx: O(n log n) vs O(n^2). **Enable for 1K+ nodes.** |
| `barnesHutTheta` | number | `0.5` | Barnes-Hut theta parameter (lower = more accurate, slower) |
| `edgeWeightInfluence` | number | `1` | How much edge weight matters |
| `gravity` | number | `1` | Pulls nodes toward center |
| `linLogMode` | boolean | `false` | Noack's LinLog model (better community separation) |
| `outboundAttractionDistribution` | boolean | `false` | Distributes attraction along outbound edges |
| `scalingRatio` | number | `1` | Higher = more spread out |
| `slowDown` | number | `1` | Higher = slower convergence, more stable |
| `strongGravityMode` | boolean | `false` | Stronger gravity, prevents disconnected components from drifting |

### Synchronous usage

```ts
import forceAtlas2 from "graphology-layout-forceatlas2";

// Returns positions map { [node]: { x, y } }
const positions = forceAtlas2(graph, { iterations: 50 });

// With custom settings
const positions = forceAtlas2(graph, {
  iterations: 100,
  settings: {
    gravity: 10,
    scalingRatio: 2,
    barnesHutOptimize: true,
  },
});

// Assign positions directly to graph nodes
forceAtlas2.assign(graph, { iterations: 50 });
```

### Auto-infer settings from graph

```ts
const sensibleSettings = forceAtlas2.inferSettings(graph);
// or from node count: forceAtlas2.inferSettings(500);

forceAtlas2.assign(graph, {
  iterations: 50,
  settings: sensibleSettings,
});
```

### Web Worker (continuous / async)

```ts
import FA2Layout from "graphology-layout-forceatlas2/worker";

const layout = new FA2Layout(graph, {
  settings: { gravity: 1, barnesHutOptimize: true },
});

layout.start();        // begin computing
layout.stop();         // pause
layout.kill();         // release memory
layout.isRunning();    // boolean
```

### React integration with @react-sigma/layout-forceatlas2

```tsx
import { useLayoutForceAtlas2, useWorkerLayoutForceAtlas2, LayoutForceAtlas2Control } from "@react-sigma/layout-forceatlas2";

// Option A: Run fixed iterations (non-iterative)
const MyLayout = () => {
  const { assign } = useLayoutForceAtlas2({ iterations: 100 });
  useEffect(() => { assign(); }, [assign]);
  return null;
};

// Option B: Worker-based continuous layout with controls
const MyLayout = () => {
  const { start, stop, kill, isRunning } = useWorkerLayoutForceAtlas2({
    settings: { gravity: 1, barnesHutOptimize: true },
  });
  useEffect(() => { start(); return () => kill(); }, [start, kill]);
  return null;
};

// Option C: Built-in control button
<SigmaContainer>
  <MyGraph />
  <ControlsContainer position="bottom-right">
    <LayoutForceAtlas2Control settings={{ gravity: 1 }} />
  </ControlsContainer>
</SigmaContainer>
```

---

## 5. Interactions: Click, Hover, Search, Filter

### Sigma.js event system

Events are typed. Payload always includes `event: { x, y, originalEvent }`.

**Node events:** `clickNode`, `rightClickNode`, `doubleClickNode`, `downNode`, `enterNode`, `leaveNode`, `wheelNode`
- Payload: `{ event, node: string }`

**Edge events:** `clickEdge`, `rightClickEdge`, `doubleClickEdge`, `downEdge`, `enterEdge`, `leaveEdge`, `wheelEdge`
- Payload: `{ event, edge: string }`
- **Must enable:** `enableEdgeClickEvents: true`, `enableEdgeHoverEvents: true`, `enableEdgeWheelEvents: true`

**Stage events:** `clickStage`, `rightClickStage`, `doubleClickStage`, `downStage`, `wheelStage`

**Lifecycle events:** `beforeRender`, `afterRender`, `resize`, `kill`

### React: useRegisterEvents hook

```tsx
import { useRegisterEvents, useSigma } from "@react-sigma/core";

const GraphEvents = () => {
  const sigma = useSigma();
  const registerEvents = useRegisterEvents();

  useEffect(() => {
    registerEvents({
      // Node click
      clickNode: ({ node, event }) => {
        console.log("Clicked node:", node);
        const attrs = sigma.getGraph().getNodeAttributes(node);
        console.log("Node attributes:", attrs);
      },
      // Node hover
      enterNode: ({ node }) => {
        document.body.style.cursor = "pointer";
        // Highlight neighbors -- see section below
      },
      leaveNode: () => {
        document.body.style.cursor = "default";
      },
      // Stage click (clicked on background)
      clickStage: () => {
        console.log("Clicked background -- deselect all");
      },
    });
  }, [registerEvents, sigma]);

  return null;
};
```

### Hover highlighting with reducers

The standard pattern for hover/selection highlighting in sigma.js uses `nodeReducer` and `edgeReducer` in settings. These functions run on every node/edge before each render and can modify display attributes without touching the graph data.

```tsx
import { useSetSettings, useSigma } from "@react-sigma/core";
import { useState, useEffect } from "react";

const HoverHighlight = () => {
  const sigma = useSigma();
  const setSettings = useSetSettings();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  useEffect(() => {
    const graph = sigma.getGraph();

    // Compute neighbor set for hovered node
    const hoveredNeighbors = hoveredNode
      ? new Set(graph.neighbors(hoveredNode))
      : null;

    setSettings({
      nodeReducer: (node, data) => {
        if (!hoveredNode) return data;
        if (node === hoveredNode || hoveredNeighbors?.has(node)) {
          return { ...data, highlighted: true };
        }
        return { ...data, color: "#E0E0E0", label: "" };
      },
      edgeReducer: (edge, data) => {
        if (!hoveredNode) return data;
        const src = graph.source(edge);
        const tgt = graph.target(edge);
        if (src === hoveredNode || tgt === hoveredNode) {
          return { ...data, color: "#FF0000", size: 3 };
        }
        return { ...data, hidden: true };
      },
    });
  }, [hoveredNode, sigma, setSettings]);

  // Register events to track hover state
  const registerEvents = useRegisterEvents();
  useEffect(() => {
    registerEvents({
      enterNode: ({ node }) => setHoveredNode(node),
      leaveNode: () => setHoveredNode(null),
    });
  }, [registerEvents]);

  return null;
};
```

### Search (find nodes by label)

```tsx
const SearchBar = () => {
  const sigma = useSigma();
  const [query, setQuery] = useState("");
  const [found, setFound] = useState<string[]>([]);

  const handleSearch = (value: string) => {
    setQuery(value);
    const graph = sigma.getGraph();
    if (!value) { setFound([]); return; }

    const lcValue = value.toLowerCase();
    const matches = graph.filterNodes(
      (node, attrs) => attrs.label?.toLowerCase().includes(lcValue)
    );
    setFound(matches);

    // Camera: focus on first match
    if (matches.length > 0) {
      const attrs = graph.getNodeAttributes(matches[0]);
      sigma.getCamera().animate({ x: attrs.x, y: attrs.y, ratio: 0.3 }, { duration: 500 });
    }
  };

  return <input value={query} onChange={e => handleSearch(e.target.value)} />;
};
```

There is also an official search package: `@react-sigma/graph-search`.

### Filter (hide nodes/edges)

Filtering is done by setting `hidden: true` on nodes/edges via reducers or directly on graph attributes:

```tsx
// Via reducer (non-destructive, recommended)
setSettings({
  nodeReducer: (node, data) => {
    if (data.type !== selectedType) return { ...data, hidden: true };
    return data;
  },
  edgeReducer: (edge, data) => {
    const graph = sigma.getGraph();
    const src = graph.getNodeAttribute(graph.source(edge), "type");
    const tgt = graph.getNodeAttribute(graph.target(edge), "type");
    if (src !== selectedType && tgt !== selectedType) return { ...data, hidden: true };
    return data;
  },
});

// Via direct attribute mutation (destructive -- modify graph data)
graph.forEachNode((node, attrs) => {
  graph.setNodeAttribute(node, "hidden", attrs.type !== selectedType);
});
```

---

## 6. Highlighting Shortest Paths

Use `graphology-shortest-path` to compute paths, then highlight via reducers.

### API

```ts
import { bidirectional } from "graphology-shortest-path";
import { dijkstra } from "graphology-shortest-path";

// Unweighted shortest path
const path: string[] | null = bidirectional(graph, sourceNode, targetNode);
// Returns array of node keys: ["a", "c", "f", "z"] or null

// Weighted shortest path (Dijkstra)
const path = dijkstra.bidirectional(graph, sourceNode, targetNode);
// Optional: custom weight attribute
const path = dijkstra.bidirectional(graph, source, target, "customWeight");
// Optional: custom weight getter
const path = dijkstra.bidirectional(graph, source, target, (_, attr) => attr.importance);

// Convert node path to edge path
import { edgePathFromNodePath } from "graphology-shortest-path";
const edgePath: string[] = edgePathFromNodePath(graph, path);
```

### Complete highlight example

```tsx
import { bidirectional } from "graphology-shortest-path";
import { edgePathFromNodePath } from "graphology-shortest-path";

const ShortestPathHighlight = ({ source, target }: { source: string; target: string }) => {
  const sigma = useSigma();
  const setSettings = useSetSettings();

  useEffect(() => {
    const graph = sigma.getGraph();
    const nodePath = bidirectional(graph, source, target);

    if (!nodePath) {
      console.log("No path found");
      return;
    }

    const pathNodeSet = new Set(nodePath);
    const pathEdges = edgePathFromNodePath(graph, nodePath);
    const pathEdgeSet = new Set(pathEdges);

    setSettings({
      nodeReducer: (node, data) => {
        if (pathNodeSet.has(node)) {
          return { ...data, color: "#FF5722", size: data.size * 1.5, highlighted: true };
        }
        return { ...data, color: "#E0E0E0", size: data.size * 0.5 };
      },
      edgeReducer: (edge, data) => {
        if (pathEdgeSet.has(edge)) {
          return { ...data, color: "#FF5722", size: 4 };
        }
        return { ...data, color: "#F0F0F0", size: 0.5 };
      },
    });

    return () => {
      setSettings({ nodeReducer: null, edgeReducer: null });
    };
  }, [source, target, sigma, setSettings]);

  return null;
};
```

---

## 7. WebGL Rendering Performance Tips for 10K+ Nodes

### Enable Barnes-Hut for layout

```ts
forceAtlas2.assign(graph, {
  iterations: 100,
  settings: {
    barnesHutOptimize: true,   // O(n log n) instead of O(n^2)
    barnesHutTheta: 0.5,
  },
});
```

### Use the FA2 web worker

Never run FA2 synchronously on 10K+ nodes in the main thread. Always use the worker:
```ts
import FA2Layout from "graphology-layout-forceatlas2/worker";
const layout = new FA2Layout(graph, { settings: { barnesHutOptimize: true } });
layout.start();
```

### Sigma settings for large graphs

```ts
const sigmaSettings = {
  // Use the most efficient node renderer
  defaultNodeType: "circle",     // NodePointProgram is fastest, but NodeCircleProgram is default

  // Hide labels during camera movement
  hideLabelsOnMove: true,

  // Hide edges when moving (huge perf gain)
  hideEdgesOnMove: true,

  // Reduce label grid density (fewer labels rendered)
  labelGridCellSize: 200,        // default is 100; higher = fewer labels
  labelRenderedSizeThreshold: 6, // only render labels for nodes above this pixel size

  // Disable edge labels (expensive)
  renderEdgeLabels: false,

  // Disable edge events if not needed (avoids edge hit-detection overhead)
  enableEdgeClickEvents: false,
  enableEdgeHoverEvents: false,
  enableEdgeWheelEvents: false,

  // zIndex sorting is expensive; disable if not needed
  zIndex: false,
};
```

### Use NodePointProgram for maximum performance

```ts
import { NodePointProgram } from "sigma/rendering";

<SigmaContainer
  settings={{
    defaultNodeType: "circle",
    nodeProgramClasses: { circle: NodePointProgram },
    // ... other settings
  }}
>
```

`NodePointProgram` uses `gl.POINTS` -- single vertex per node, maximum throughput. Limitation: nodes can't exceed 100px radius.

### Batch graph mutations

```ts
// BAD: triggers many re-renders
nodes.forEach(n => graph.addNode(n.id, n.attrs));

// GOOD: import all at once
graph.import({
  nodes: nodes.map(n => ({ key: n.id, attributes: n.attrs })),
  edges: edges.map(e => ({ source: e.src, target: e.tgt, attributes: e.attrs })),
});
```

### Avoid EdgeArrowProgram for large graphs

`EdgeArrowProgram` is a composite (body + head), twice the draw calls. Use `EdgeLineProgram` (1px lines but very fast) or `EdgeRectangleProgram` (default, thick lines, single program) instead.

### Level-of-detail rendering with reducers

```ts
setSettings({
  nodeReducer: (node, data) => {
    // Hide small nodes when zoomed out
    const ratio = sigma.getCamera().ratio;
    if (data.size * ratio < 2) return { ...data, hidden: true };
    return data;
  },
});
```

### Webpack caveat

Avoid `cheap-eval`-like `devtool` options in webpack config when using FA2 worker. It causes severe performance degradation.

---

## 8. Styling Nodes and Edges

### Node attributes recognized by sigma

| Attribute | Type | Description |
|---|---|---|
| `x`, `y` | number | Position (required for rendering) |
| `size` | number | Radius in pixels at default zoom |
| `color` | string | Hex (`"#e22653"`) or CSS named color (`"deeppink"`) |
| `label` | string | Text displayed near node |
| `type` | string | Key into `nodeProgramClasses` (e.g. `"circle"`, `"square"`) |
| `hidden` | boolean | If `true`, node is not rendered |
| `forceLabel` | boolean | Always show label regardless of zoom |
| `zIndex` | number | Draw order (requires `zIndex: true` in settings) |

### Edge attributes recognized by sigma

| Attribute | Type | Description |
|---|---|---|
| `size` | number | Thickness in pixels |
| `color` | string | Hex or CSS named color |
| `label` | string | Text near edge (requires `renderEdgeLabels: true`) |
| `type` | string | Key into `edgeProgramClasses` (e.g. `"line"`, `"arrow"`) |
| `hidden` | boolean | If `true`, edge is not rendered |
| `forceLabel` | boolean | Always show label |
| `zIndex` | number | Draw order (edges are always behind nodes) |

### Setting colors and sizes on graph data

```ts
graph.addNode("server1", {
  x: 0, y: 0,
  size: 20,
  color: "#e74c3c",
  label: "MCP Server",
  type: "circle",
});

graph.addEdge("agent1", "server1", {
  size: 2,
  color: "#95a5a6",
  label: "tool_call",
  type: "arrow",   // requires EdgeArrowProgram registered
});
```

### Registering edge/node programs

```tsx
import { NodeCircleProgram, NodePointProgram } from "sigma/rendering";
import { EdgeArrowProgram, EdgeRectangleProgram } from "sigma/rendering";
import { createEdgeArrowProgram } from "sigma/rendering";

<SigmaContainer
  settings={{
    defaultNodeType: "circle",
    defaultEdgeType: "arrow",
    nodeProgramClasses: {
      circle: NodeCircleProgram,
      point: NodePointProgram,
    },
    edgeProgramClasses: {
      line: EdgeRectangleProgram,       // thick lines (default)
      arrow: EdgeArrowProgram,          // directed arrows
    },
  }}
>
```

### Label settings

```ts
const settings = {
  labelFont: "Inter, sans-serif",
  labelSize: 14,
  labelWeight: "bold",       // CSS font-weight value
  labelColor: { color: "#333" },
  // OR per-node attribute:
  // labelColor: { attribute: "labelColor", color: "#333" },

  renderEdgeLabels: true,
  edgeLabelFont: "Inter, sans-serif",
  edgeLabelSize: 12,
  edgeLabelWeight: "normal",
  edgeLabelColor: { color: "#999" },
};
```

### Dynamic styling with reducers

The reducers pattern is the canonical way to do conditional/interactive styling without mutating graph data:

```ts
setSettings({
  nodeReducer: (node, data) => {
    const nodeType = sigma.getGraph().getNodeAttribute(node, "nodeType");
    const colorMap: Record<string, string> = {
      agent: "#3498db",
      server: "#e74c3c",
      tool: "#2ecc71",
      resource: "#f39c12",
    };
    return {
      ...data,
      color: colorMap[nodeType] || data.color,
      size: nodeType === "agent" ? 20 : 10,
    };
  },
});
```

### Additional node program packages

- `@sigma/node-image` -- nodes with images (texture atlas)
- `@sigma/node-border` -- concentric disc borders
- `@sigma/node-piechart` -- pie-chart nodes
- `@sigma/node-square` -- square nodes
- `@sigma/edge-curve` -- curved edges

---

## 9. Complete React Component Example

This example puts together: graph loading, ForceAtlas2 layout, hover highlighting, node search, and shortest path display.

```tsx
import { FC, useEffect, useState, useMemo } from "react";
import Graph from "graphology";
import {
  SigmaContainer,
  useLoadGraph,
  useRegisterEvents,
  useSetSettings,
  useSigma,
  ControlsContainer,
  ZoomControl,
  FullScreenControl,
} from "@react-sigma/core";
import { LayoutForceAtlas2Control } from "@react-sigma/layout-forceatlas2";
import { useWorkerLayoutForceAtlas2 } from "@react-sigma/layout-forceatlas2";
import { random } from "graphology-layout";
import { bidirectional } from "graphology-shortest-path";
import { edgePathFromNodePath } from "graphology-shortest-path";
import { EdgeArrowProgram } from "sigma/rendering";
import "@react-sigma/core/lib/style.css";

// ── Graph loader ──────────────────────────────────────────
const LoadGraphData: FC = () => {
  const loadGraph = useLoadGraph();

  useEffect(() => {
    const graph = new Graph();

    // Add nodes
    const nodeTypes = ["agent", "server", "tool", "resource"];
    const colors: Record<string, string> = {
      agent: "#3498db",
      server: "#e74c3c",
      tool: "#2ecc71",
      resource: "#f39c12",
    };

    for (let i = 0; i < 50; i++) {
      const nodeType = nodeTypes[i % nodeTypes.length];
      graph.addNode(`node-${i}`, {
        label: `${nodeType}-${i}`,
        size: nodeType === "agent" ? 15 : 8,
        color: colors[nodeType],
        nodeType,
      });
    }

    // Add edges
    for (let i = 0; i < 80; i++) {
      const src = `node-${Math.floor(Math.random() * 50)}`;
      const tgt = `node-${Math.floor(Math.random() * 50)}`;
      if (src !== tgt && !graph.hasEdge(src, tgt)) {
        graph.addEdge(src, tgt, { size: 1, color: "#ccc" });
      }
    }

    // Assign random positions (required before FA2)
    random.assign(graph);

    loadGraph(graph);
  }, [loadGraph]);

  return null;
};

// ── Layout controller ─────────────────────────────────────
const LayoutController: FC = () => {
  const { start, stop, kill, isRunning } = useWorkerLayoutForceAtlas2({
    settings: {
      gravity: 1,
      barnesHutOptimize: true,
      slowDown: 5,
    },
  });

  useEffect(() => {
    start();
    // Auto-stop after 3 seconds to let it settle
    const timer = setTimeout(() => stop(), 3000);
    return () => { clearTimeout(timer); kill(); };
  }, [start, stop, kill]);

  return null;
};

// ── Interactions: hover + click + shortest path ───────────
const GraphInteractions: FC<{
  pathSource: string | null;
  pathTarget: string | null;
}> = ({ pathSource, pathTarget }) => {
  const sigma = useSigma();
  const setSettings = useSetSettings();
  const registerEvents = useRegisterEvents();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Register mouse events
  useEffect(() => {
    registerEvents({
      enterNode: ({ node }) => {
        setHoveredNode(node);
        document.body.style.cursor = "pointer";
      },
      leaveNode: () => {
        setHoveredNode(null);
        document.body.style.cursor = "default";
      },
    });
  }, [registerEvents]);

  // Compute shortest path
  const pathData = useMemo(() => {
    if (!pathSource || !pathTarget) return null;
    const graph = sigma.getGraph();
    const nodePath = bidirectional(graph, pathSource, pathTarget);
    if (!nodePath) return null;
    return {
      nodes: new Set(nodePath),
      edges: new Set(edgePathFromNodePath(graph, nodePath)),
    };
  }, [pathSource, pathTarget, sigma]);

  // Apply reducers for hover + path highlighting
  useEffect(() => {
    const graph = sigma.getGraph();
    const hoveredNeighbors = hoveredNode ? new Set(graph.neighbors(hoveredNode)) : null;

    setSettings({
      nodeReducer: (node, data) => {
        const res = { ...data };

        // Path highlighting takes priority
        if (pathData) {
          if (pathData.nodes.has(node)) {
            res.color = "#FF5722";
            res.size = data.size * 1.5;
            res.highlighted = true;
          } else {
            res.color = "#E0E0E0";
          }
          return res;
        }

        // Hover highlighting
        if (hoveredNode) {
          if (node === hoveredNode || hoveredNeighbors?.has(node)) {
            res.highlighted = true;
          } else {
            res.color = "#E0E0E0";
            res.label = "";
          }
        }

        return res;
      },
      edgeReducer: (edge, data) => {
        const res = { ...data };

        if (pathData) {
          if (pathData.edges.has(edge)) {
            return { ...res, color: "#FF5722", size: 4 };
          }
          return { ...res, hidden: true };
        }

        if (hoveredNode) {
          const src = graph.source(edge);
          const tgt = graph.target(edge);
          if (src === hoveredNode || tgt === hoveredNode) {
            return { ...res, color: "#FF0000", size: 2 };
          }
          return { ...res, hidden: true };
        }

        return res;
      },
    });
  }, [hoveredNode, pathData, sigma, setSettings]);

  return null;
};

// ── Search bar component ──────────────────────────────────
const SearchBar: FC<{ onSelect: (node: string) => void }> = ({ onSelect }) => {
  const sigma = useSigma();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<string[]>([]);

  const handleSearch = (value: string) => {
    setQuery(value);
    if (!value) { setResults([]); return; }
    const graph = sigma.getGraph();
    const lc = value.toLowerCase();
    setResults(graph.filterNodes((_, attrs) => attrs.label?.toLowerCase().includes(lc)).slice(0, 10));
  };

  return (
    <div style={{ position: "absolute", top: 10, left: 10, zIndex: 1, background: "#fff", padding: 8 }}>
      <input
        type="text"
        placeholder="Search nodes..."
        value={query}
        onChange={(e) => handleSearch(e.target.value)}
      />
      {results.map((node) => (
        <div
          key={node}
          onClick={() => {
            onSelect(node);
            const attrs = sigma.getGraph().getNodeAttributes(node);
            sigma.getCamera().animate({ x: attrs.x, y: attrs.y, ratio: 0.1 }, { duration: 500 });
          }}
          style={{ cursor: "pointer", padding: "2px 4px" }}
        >
          {sigma.getGraph().getNodeAttribute(node, "label")}
        </div>
      ))}
    </div>
  );
};

// ── Main App component ────────────────────────────────────
export const AgentHoundGraph: FC = () => {
  const [pathSource, setPathSource] = useState<string | null>(null);
  const [pathTarget, setPathTarget] = useState<string | null>(null);

  return (
    <SigmaContainer
      style={{ height: "100vh", width: "100%" }}
      settings={{
        defaultEdgeType: "arrow",
        edgeProgramClasses: { arrow: EdgeArrowProgram },
        renderEdgeLabels: false,
        hideEdgesOnMove: true,
        hideLabelsOnMove: true,
        labelGridCellSize: 150,
        labelRenderedSizeThreshold: 6,
        enableEdgeClickEvents: false,
        enableEdgeHoverEvents: false,
      }}
    >
      <LoadGraphData />
      <LayoutController />
      <GraphInteractions pathSource={pathSource} pathTarget={pathTarget} />
      <SearchBar onSelect={(node) => {
        if (!pathSource) setPathSource(node);
        else if (!pathTarget) setPathTarget(node);
        else { setPathSource(node); setPathTarget(null); }
      }} />
      <ControlsContainer position="bottom-right">
        <ZoomControl />
        <FullScreenControl />
        <LayoutForceAtlas2Control settings={{ gravity: 1 }} />
      </ControlsContainer>
    </SigmaContainer>
  );
};
```

---

## Sources

- https://www.npmjs.com/package/sigma (v3.0.2)
- https://www.npmjs.com/package/graphology (v0.26.0)
- https://www.npmjs.com/package/@react-sigma/core (v5.0.6)
- https://www.npmjs.com/package/graphology-layout-forceatlas2 (v0.10.1)
- https://www.npmjs.com/package/@react-sigma/layout-forceatlas2 (v5.0.6)
- https://graphology.github.io/mutation.html
- https://graphology.github.io/standard-library/layout-forceatlas2.html
- https://graphology.github.io/standard-library/shortest-path.html
- https://www.sigmajs.org/docs/advanced/events/
- https://www.sigmajs.org/docs/advanced/renderers/
- https://www.sigmajs.org/docs/advanced/customization
- https://www.sigmajs.org/docs/advanced/data/
- https://www.sigmajs.org/docs/advanced/sizes
- https://sim51.github.io/react-sigma/docs/start-introduction
- https://sim51.github.io/react-sigma/docs/start-setup
- https://sim51.github.io/react-sigma/docs/api/core/
- https://sim51.github.io/react-sigma/docs/api (project structure / layout modules)
- https://lyonwj.com/blog/sigma-react-graph-visualization
