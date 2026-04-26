import { describe, it, expect } from "vitest";
import { extractCriticalChains } from "@/lib/explorer/critical-chains";
import type { Finding } from "@/api/types";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "critical",
    category: "Transitive Access",
    title: "Critical path",
    description: "",
    edge_kind: "CAN_REACH",
    source_id: "src",
    source_name: "source",
    source_kind: "AgentInstance",
    target_id: "tgt",
    target_name: "target",
    target_kind: "MCPResource",
    confidence: 0.9,
    owasp_map: [],
    ...overrides,
  };
}

describe("extractCriticalChains", () => {
  it("ignores non-critical findings", () => {
    const findings = [
      finding({ id: "a", severity: "high" }),
      finding({ id: "b", severity: "critical" }),
      finding({ id: "c", severity: "medium" }),
    ];
    const chains = extractCriticalChains(findings);
    expect(chains).toHaveLength(1);
    expect(chains[0]?.findingId).toBe("b");
  });

  it("sorts by confidence descending", () => {
    const findings = [
      finding({ id: "a", confidence: 0.7 }),
      finding({ id: "b", confidence: 0.95 }),
      finding({ id: "c", confidence: 0.85 }),
    ];
    const chains = extractCriticalChains(findings);
    expect(chains.map((c) => c.findingId)).toEqual(["b", "c", "a"]);
  });

  it("breaks ties by source name alphabetically", () => {
    const findings = [
      finding({ id: "a", source_name: "zulu", confidence: 0.8 }),
      finding({ id: "b", source_name: "alpha", confidence: 0.8 }),
    ];
    const chains = extractCriticalChains(findings);
    expect(chains.map((c) => c.findingId)).toEqual(["b", "a"]);
  });

  it("falls back to ID slice when names are empty", () => {
    const findings = [
      finding({
        id: "a",
        source_name: "",
        target_name: "",
        source_id: "0123456789abcdef",
        target_id: "fedcba9876543210",
      }),
    ];
    const chains = extractCriticalChains(findings);
    expect(chains[0]?.sourceName).toBe("0123456789ab");
    expect(chains[0]?.targetName).toBe("fedcba987654");
  });

  it("returns empty for empty input", () => {
    expect(extractCriticalChains([])).toEqual([]);
  });
});
