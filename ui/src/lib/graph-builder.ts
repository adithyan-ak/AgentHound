import type { Node, Edge } from "@xyflow/react";
import type { APINode, APIEdge } from "@/api/types";
import { getNodeColor, getNodeSize, getNodeLabel } from "./node-styles";
import { getEdgeCategory } from "./edge-styles";

const STRUCTURAL_EDGE_KINDS = new Set([
  "TRUSTS_SERVER",
  "PROVIDES_TOOL",
  "PROVIDES_RESOURCE",
  "PROVIDES_PROMPT",
  "ADVERTISES_SKILL",
]);

const NODE_TYPE_MAP: Record<string, string> = {
  AgentInstance: "agentZone",
  MCPServer: "server",
  MCPTool: "tool",
  MCPPrompt: "tool",
  MCPResource: "resource",
  A2AAgent: "a2aAgent",
  A2ASkill: "skill",
  Identity: "infra",
  Credential: "infra",
  Host: "infra",
  ConfigFile: "infra",
  InstructionFile: "infra",
  ResourceGroup: "infra",
  TrustZone: "infra",
};

const MAX_TOOLS_PER_SERVER = 8;

export function buildReactFlowGraph(
  apiNodes: APINode[],
  apiEdges: APIEdge[],
): { nodes: Node[]; edges: Edge[] } {
  const nodeMap = new Map<string, APINode>();
  for (const n of apiNodes) nodeMap.set(n.id, n);

  const childrenOf = new Map<string, Set<string>>();
  const parentOf = new Map<string, string>();

  for (const edge of apiEdges) {
    if (STRUCTURAL_EDGE_KINDS.has(edge.kind)) {
      if (!childrenOf.has(edge.source)) childrenOf.set(edge.source, new Set());
      childrenOf.get(edge.source)!.add(edge.target);
      if (!parentOf.has(edge.target)) {
        parentOf.set(edge.target, edge.source);
      }
    }
  }

  const groupOf = new Map<string, string>();

  for (const node of apiNodes) {
    const kind = node.kinds[0] ?? "";
    if (kind === "AgentInstance") {
      groupOf.set(node.id, node.id);
      const visited = new Set<string>([node.id]);
      const queue = [node.id];
      while (queue.length > 0) {
        const current = queue.shift()!;
        const children = childrenOf.get(current);
        if (!children) continue;
        for (const child of children) {
          if (!visited.has(child)) {
            visited.add(child);
            groupOf.set(child, node.id);
            queue.push(child);
          }
        }
      }
    }
  }

  for (const node of apiNodes) {
    if (!groupOf.has(node.id)) {
      groupOf.set(node.id, "orphan");
    }
  }

  const toolsByServer = new Map<string, string[]>();
  for (const edge of apiEdges) {
    if (edge.kind === "PROVIDES_TOOL" || edge.kind === "PROVIDES_PROMPT") {
      if (!toolsByServer.has(edge.source)) toolsByServer.set(edge.source, []);
      toolsByServer.get(edge.source)!.push(edge.target);
    }
  }

  const hiddenOverflowIds = new Set<string>();
  for (const [, toolIds] of toolsByServer) {
    for (let i = MAX_TOOLS_PER_SERVER; i < toolIds.length; i++) {
      hiddenOverflowIds.add(toolIds[i]!);
    }
  }

  const nodes: Node[] = [];

  const agentNodes = apiNodes.filter((n) => n.kinds[0] === "AgentInstance");
  for (const agent of agentNodes) {
    nodes.push({
      id: agent.id,
      type: "agentZone",
      position: { x: 0, y: 0 },
      data: {
        label: getNodeLabel(agent),
        kind: "AgentInstance",
        color: getNodeColor(agent.kinds),
        riskScore: Number(agent.properties.risk_score ?? 0),
        properties: agent.properties,
        serverCount: 0,
        toolCount: 0,
      },
      style: { width: 400, height: 300 },
    });
  }

  const hasOrphans = apiNodes.some(
    (n) => n.kinds[0] !== "AgentInstance" && groupOf.get(n.id) === "orphan",
  );
  if (hasOrphans) {
    nodes.push({
      id: "orphan",
      type: "agentZone",
      position: { x: 0, y: 0 },
      data: {
        label: "Infrastructure",
        kind: "AgentInstance",
        color: "#8E8E93",
        riskScore: 0,
        properties: {},
        serverCount: 0,
        toolCount: 0,
      },
      style: { width: 300, height: 200 },
    });
  }

  for (const node of apiNodes) {
    const kind = node.kinds[0] ?? "Unknown";
    if (kind === "AgentInstance") continue;

    const group = groupOf.get(node.id) ?? "orphan";
    const nodeType = NODE_TYPE_MAP[kind] ?? "infra";

    if (hiddenOverflowIds.has(node.id)) continue;

    nodes.push({
      id: node.id,
      type: nodeType,
      position: { x: 0, y: 0 },
      parentId: group,
      extent: "parent" as const,
      data: {
        label: getNodeLabel(node),
        kind,
        color: getNodeColor(node.kinds),
        size: getNodeSize(node),
        riskScore: Number(node.properties.risk_score ?? 0),
        properties: node.properties,
      },
    });
  }

  for (const [serverId, toolIds] of toolsByServer) {
    if (toolIds.length > MAX_TOOLS_PER_SERVER) {
      const overflowCount = toolIds.length - MAX_TOOLS_PER_SERVER;
      const group = groupOf.get(serverId) ?? "orphan";
      nodes.push({
        id: `overflow-${serverId}`,
        type: "tool",
        position: { x: 0, y: 0 },
        parentId: group,
        extent: "parent" as const,
        data: {
          label: `${overflowCount} more tools...`,
          kind: "MCPTool",
          color: "#F5A623",
          size: 6,
          riskScore: 0,
          properties: {},
          isOverflow: true,
          overflowCount,
        },
      });
    }
  }

  const srvCount = new Map<string, number>();
  const tlCount = new Map<string, number>();
  for (const node of nodes) {
    if (!node.parentId) continue;
    const k = (node.data as Record<string, unknown>).kind as string;
    if (k === "MCPServer") srvCount.set(node.parentId, (srvCount.get(node.parentId) ?? 0) + 1);
    if (k === "MCPTool" || k === "MCPPrompt") tlCount.set(node.parentId, (tlCount.get(node.parentId) ?? 0) + 1);
  }
  for (const node of nodes) {
    if (node.type === "agentZone") {
      (node.data as Record<string, unknown>).serverCount = srvCount.get(node.id) ?? 0;
      (node.data as Record<string, unknown>).toolCount = tlCount.get(node.id) ?? 0;
    }
  }

  const edges: Edge[] = [];
  const seen = new Set<string>();

  for (const edge of apiEdges) {
    if (!nodeMap.has(edge.source) || !nodeMap.has(edge.target)) continue;
    if (hiddenOverflowIds.has(edge.source) || hiddenOverflowIds.has(edge.target)) continue;

    const key = `${edge.source}->${edge.target}:${edge.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);

    edges.push({
      id: key,
      source: edge.source,
      target: edge.target,
      type: getEdgeCategory(edge.kind),
      data: { kind: edge.kind, properties: edge.properties },
    });
  }

  return { nodes, edges };
}
