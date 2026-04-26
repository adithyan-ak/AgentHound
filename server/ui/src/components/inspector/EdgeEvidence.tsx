import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  FileText,
  Link as LinkIcon,
  Shield,
  Zap,
} from "lucide-react";
import { fetchEdges } from "@/api/graph";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { getEdgeCategory } from "@/lib/edge-styles";
import { cn } from "@/lib/utils";

interface EdgeEvidenceProps {
  edgeId: string;
}

function parseEdgeId(id: string): { source: string; target: string; kind: string } | null {
  const m = id.match(/^(.+)->(.+):([^:]+)$/);
  if (!m || !m[1] || !m[2] || !m[3]) return null;
  return { source: m[1], target: m[2], kind: m[3] };
}

const EDGE_EXPLOIT: Record<string, { title: string; detail: string }> = {
  CAN_REACH: {
    title: "Transitive reachability",
    detail:
      "This agent can reach the target resource through a chain of trusted servers and tools. An attacker controlling the agent can invoke this chain end-to-end without any additional privilege escalation.",
  },
  CAN_EXFILTRATE_VIA: {
    title: "Exfiltration route",
    detail:
      "The source agent has access to sensitive data AND has a tool with outbound network capability. This combination allows silent exfiltration — the agent can read the data and send it out in a single interaction.",
  },
  CAN_EXECUTE: {
    title: "Shell / code execution",
    detail:
      "This tool is classified as having shell_access or code_execution capability. An attacker invoking this tool through the agent gains command execution on the target host.",
  },
  POISONED_DESCRIPTION: {
    title: "Tool description injection",
    detail:
      "This tool's description contains prompt-injection patterns. An LLM reading the tool list may follow instructions hidden in the description rather than the user's intent.",
  },
  POISONED_INSTRUCTIONS: {
    title: "Instruction file poisoning",
    detail:
      "An instruction file loaded by the agent (AGENTS.md / CLAUDE.md / cursorrules / etc.) contains suspicious imperative overrides or hidden Unicode.",
  },
  SHADOWS: {
    title: "Tool name shadowing",
    detail:
      "This tool's description references another server's tool by name, creating a confused-deputy risk where the LLM may call the wrong tool.",
  },
  CAN_IMPERSONATE: {
    title: "Agent impersonation",
    detail:
      "This A2A agent's skill descriptions are >80% similar to another agent's. A downstream caller may be tricked into delegating to the wrong agent.",
  },
  HAS_ACCESS_TO: {
    title: "Direct resource access",
    detail:
      "Based on capability surface and URI scheme match, this tool can read or write this resource.",
  },
  TRUSTS_SERVER: {
    title: "Configured trust",
    detail:
      "This agent's config file declares trust in this MCP server. The agent will send all tool lists and invoke all listed tools without further authentication checks on the user side.",
  },
  DELEGATES_TO: {
    title: "A2A delegation",
    detail:
      "This A2A agent delegates tasks to the target. Any capability the target has becomes transitively available to the source agent.",
  },
};

export function EdgeEvidence({ edgeId }: EdgeEvidenceProps) {
  const parsed = parseEdgeId(edgeId);
  const { data: edges, isLoading } = useQuery({
    queryKey: ["edges", "all"],
    queryFn: () => fetchEdges(undefined, 100000),
    staleTime: 30_000,
    enabled: !!parsed,
  });

  if (!parsed) {
    return (
      <div className="p-4 text-xs text-muted-foreground">
        Unknown edge format
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-4">
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  const edge = edges?.find(
    (e) =>
      e.source === parsed.source &&
      e.target === parsed.target &&
      e.kind === parsed.kind,
  );

  if (!edge) {
    return (
      <div className="p-4 text-xs text-muted-foreground">
        Edge not found. It may have been removed since the last scan.
      </div>
    );
  }

  const category = getEdgeCategory(edge.kind);
  const exploit = EDGE_EXPLOIT[edge.kind];
  const riskWeight = Number(edge.properties?.risk_weight ?? 0);
  const confidence = Number(edge.properties?.confidence ?? 0);
  const isComposite = Boolean(edge.properties?.is_composite);
  const sourceCollector = String(edge.properties?.source_collector ?? "");
  const evidence = edge.properties?.evidence;
  const owaspTags = Array.isArray(edge.properties?.owasp_map)
    ? (edge.properties.owasp_map as string[])
    : [];
  const sourceKind = edge.source_kind ?? "";
  const targetKind = edge.target_kind ?? "";
  const isCrossProtocol =
    (sourceKind.startsWith("A2A") && targetKind.startsWith("MCP")) ||
    (sourceKind.startsWith("MCP") && targetKind.startsWith("A2A"));

  return (
    <div className="p-4 space-y-3 text-xs">
      {/* Header */}
      <div>
        <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
          <Badge
            variant="outline"
            className={cn(
              "text-[9px] font-semibold uppercase",
              category === "attack"
                ? "border-red-500/50 bg-red-950/40 text-red-300"
                : category === "trust"
                  ? "border-blue-500/50 bg-blue-950/40 text-blue-300"
                  : "border-border bg-muted text-muted-foreground",
            )}
          >
            {category}
          </Badge>
          {isCrossProtocol && (
            <Badge className="text-[9px] bg-amber-500 text-black hover:bg-amber-500 uppercase font-bold">
              cross-protocol
            </Badge>
          )}
          {isComposite && (
            <Badge variant="outline" className="text-[9px]">
              composite
            </Badge>
          )}
          {owaspTags.map((tag) => (
            <Badge key={tag} variant="secondary" className="text-[9px] font-mono">
              {tag}
            </Badge>
          ))}
        </div>
        <div className="text-sm font-semibold text-foreground font-mono break-all">
          {edge.kind}
        </div>
      </div>

      {/* Source -> Target */}
      <div className="rounded border border-border bg-background/40 p-2 text-[11px]">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-muted-foreground">From</span>
          <span className="font-mono text-foreground break-all">
            {parsed.source.slice(0, 20)}...
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <ArrowRight className="h-3 w-3 text-red-400" />
          <span className="font-mono text-foreground break-all">
            {parsed.target.slice(0, 20)}...
          </span>
        </div>
      </div>

      {/* Risk + Confidence */}
      {(riskWeight > 0 || confidence > 0) && (
        <div className="grid grid-cols-2 gap-2">
          {riskWeight > 0 && (
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="flex items-center gap-1 text-muted-foreground mb-1">
                <Zap className="h-3 w-3" />
                <span>Risk weight</span>
              </div>
              <div className="text-foreground font-mono text-sm">
                {riskWeight.toFixed(2)}
              </div>
            </div>
          )}
          {confidence > 0 && (
            <div className="rounded border border-border bg-background/40 p-2">
              <div className="flex items-center gap-1 text-muted-foreground mb-1">
                <Shield className="h-3 w-3" />
                <span>Confidence</span>
              </div>
              <div className="text-foreground font-mono text-sm">
                {(confidence * 100).toFixed(0)}%
              </div>
            </div>
          )}
        </div>
      )}

      {/* Exploit explanation */}
      {exploit && (
        <div className="rounded border border-red-900/40 bg-red-950/20 p-2.5">
          <div className="flex items-center gap-1.5 mb-1">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
            <span className="text-[11px] font-semibold text-red-300">
              {exploit.title}
            </span>
          </div>
          <p className="text-[11px] text-foreground/80 leading-relaxed">
            {exploit.detail}
          </p>
        </div>
      )}

      {/* Evidence blob */}
      {evidence != null && (
        <div className="rounded border border-border bg-background/40 p-2">
          <div className="flex items-center gap-1 text-muted-foreground mb-1">
            <FileText className="h-3 w-3" />
            <span>Evidence</span>
          </div>
          <pre className="text-[10px] text-foreground font-mono whitespace-pre-wrap break-all">
            {typeof evidence === "string"
              ? evidence
              : JSON.stringify(evidence, null, 2)}
          </pre>
        </div>
      )}

      {/* Source collector */}
      {sourceCollector && (
        <div className="flex items-center gap-1.5 text-muted-foreground text-[10px]">
          <LinkIcon className="h-3 w-3" />
          <span>
            Detected by{" "}
            <span className="text-foreground font-mono">{sourceCollector}</span>{" "}
            collector
          </span>
        </div>
      )}
    </div>
  );
}
