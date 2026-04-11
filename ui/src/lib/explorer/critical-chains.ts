import type { Finding } from "@/api/types";
import type { SeverityLevel } from "./lens-config";

export interface CriticalChain {
  id: string;
  sourceId: string;
  sourceName: string;
  sourceKind: string;
  targetId: string;
  targetName: string;
  targetKind: string;
  severity: SeverityLevel;
  category: string;
  title: string;
  description: string;
  edgeKind: string;
  confidence: number;
  owaspMap: string[];
  /**
   * The underlying finding ID, used for drill-in.
   */
  findingId: string;
}

/**
 * Extract critical attack chains from the findings list. A "chain" for the
 * purposes of the Critical lens is a single critical-severity finding
 * represented as a display card. We rank them by confidence (desc), then
 * severity (critical first), then source name for stability.
 */
export function extractCriticalChains(findings: Finding[]): CriticalChain[] {
  const chains: CriticalChain[] = [];
  for (const f of findings) {
    if (f.severity !== "critical") continue;
    chains.push({
      id: `chain-${f.id}`,
      sourceId: f.source_id,
      sourceName: f.source_name || f.source_id.slice(0, 12),
      sourceKind: f.source_kind,
      targetId: f.target_id,
      targetName: f.target_name || f.target_id.slice(0, 12),
      targetKind: f.target_kind,
      severity: "critical",
      category: f.category,
      title: f.title,
      description: f.description,
      edgeKind: f.edge_kind,
      confidence: f.confidence,
      owaspMap: f.owasp_map ?? [],
      findingId: f.id,
    });
  }
  chains.sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return a.sourceName.localeCompare(b.sourceName);
  });
  return chains;
}
