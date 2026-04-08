import { MultiDirectedGraph } from "graphology";
import { SigmaContainer } from "@react-sigma/core";
import "@react-sigma/core/lib/style.css";
import { GraphDataLoader } from "./GraphDataLoader";
import { GraphEvents } from "./GraphEvents";
import { GraphControls } from "./GraphControls";
import { GraphSearch } from "./GraphSearch";
import { GraphFilters } from "./GraphFilters";
import { GraphLegend } from "./GraphLegend";
import { useGraphStore } from "@/store/graph";
import { NODE_COLORS } from "@/lib/node-styles";

const sigmaSettings = {
  defaultNodeColor: "#999",
  defaultEdgeColor: "#ccc",
  labelRenderedSizeThreshold: 12,
  renderEdgeLabels: false,
  enableEdgeEvents: true,
  labelFont: "Inter, system-ui, sans-serif",
  labelSize: 12,
  labelColor: { color: "#333" },
  edgeLabelFont: "Inter, system-ui, sans-serif",
  edgeLabelSize: 10,
  nodeReducer: undefined as
    | ((node: string, data: Record<string, unknown>) => Record<string, unknown>)
    | undefined,
  edgeReducer: undefined as
    | ((
        edge: string,
        data: Record<string, unknown>,
      ) => Record<string, unknown>)
    | undefined,
};

export function GraphExplorer() {
  const hoveredNode = useGraphStore((s) => s.hoveredNodeId);
  const selectedNode = useGraphStore((s) => s.selectedNodeId);
  const highlightedPath = useGraphStore((s) => s.highlightedPath);
  const filters = useGraphStore((s) => s.activeFilters);

  const settings = {
    ...sigmaSettings,
    nodeReducer: (node: string, data: Record<string, unknown>) => {
      const res = { ...data };
      const kind = data._kind as string;

      if (!filters.nodeKinds.has(kind)) {
        res.hidden = true;
        return res;
      }

      const riskScore = Number(data._riskScore ?? 0);
      if (riskScore < filters.minRiskScore) {
        res.hidden = true;
        return res;
      }

      if (highlightedPath) {
        const onPath = highlightedPath.nodeIds.includes(node);
        res.color = onPath
          ? (NODE_COLORS[kind] ?? "#999")
          : "#333";
        res.size = onPath
          ? (data.size as number) * 1.5
          : (data.size as number) * 0.4;
        res.zIndex = onPath ? 1 : 0;
        return res;
      }

      if (hoveredNode) {
        if (node === hoveredNode || node === selectedNode) {
          res.zIndex = 1;
        } else {
          res.color = "#333";
          res.size = (data.size as number) * 0.6;
          res.label = "";
        }
      }

      if (node === selectedNode) {
        res.highlighted = true;
        res.zIndex = 2;
      }

      return res;
    },
    edgeReducer: (edge: string, data: Record<string, unknown>) => {
      const res = { ...data };
      const kind = data._kind as string;

      if (!filters.edgeKinds.has(kind)) {
        res.hidden = true;
        return res;
      }

      if (highlightedPath) {
        const onPath = highlightedPath.edgeKeys.includes(edge);
        res.color = onPath ? "#FF0000" : "#222";
        res.size = onPath ? 3 : 0.3;
        res.zIndex = onPath ? 1 : 0;
        return res;
      }

      if (hoveredNode) {
        res.color = "#222";
        res.size = 0.5;
      }

      return res;
    },
  };

  return (
    <div className="relative h-full w-full">
      <SigmaContainer
        graph={MultiDirectedGraph}
        settings={settings}
        className="h-full w-full"
      >
        <GraphDataLoader />
        <GraphEvents />
        <GraphSearch />
      </SigmaContainer>
      <GraphControls />
      <GraphFilters />
      <GraphLegend />
    </div>
  );
}
