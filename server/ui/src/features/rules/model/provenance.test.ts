import { describe, expect, it } from "vitest";
import type { Scan } from "@entities/scan";
import { scanRulesetProvenance } from "./provenance";

function scan(metadata?: Record<string, unknown>): Scan {
  return {
    id: "scan-1",
    collector: "mcp",
    status: "completed",
    started_at: "2026-07-11T00:00:00Z",
    completed_at: "2026-07-11T00:01:00Z",
    submitted: { nodes: 1, edges: 1 },
    write_rows: { nodes: 1, edges: 1 },
    graph_totals: { before: null, after: null },
    metadata,
  };
}

describe("scanRulesetProvenance", () => {
  it("parses the scan-specific effective rule manifest", () => {
    const result = scanRulesetProvenance(
      scan({
        ruleset: {
          digest: "sha256:rules",
          load_state: "complete",
          authenticity: "unverified",
          entries: [
            {
              type: "text",
              id: "prompt-injection",
              version: 3,
              semantic_sha256: "sha256:entry",
              source: "custom",
              effective_matcher: {
                type: "keyword",
                keywords: ["prompt"],
              },
            },
          ],
          errors: [],
        },
      }),
    );

    expect(result.manifest?.digest).toBe("sha256:rules");
    expect(result.manifest?.entries[0]).toMatchObject({
      id: "prompt-injection",
      version: 3,
      source: "custom",
      effective_matcher: {
        type: "keyword",
        keywords: ["prompt"],
      },
    });
    expect(result.manifest?.authenticity).toBe("unverified");
  });

  it("does not substitute current rules when scan provenance is absent", () => {
    const result = scanRulesetProvenance(scan());

    expect(result.manifest).toBeNull();
    expect(result.issue).toMatch(/predates rule provenance/i);
  });

  it("rejects malformed effective matcher metadata", () => {
    const result = scanRulesetProvenance(
      scan({
        ruleset: {
          entries: [
            {
              type: "text",
              id: "bad",
              version: 1,
              semantic_sha256: "sha256:bad",
              source: "custom",
              effective_matcher: "not-an-object",
            },
          ],
        },
      }),
    );

    expect(result.manifest).toBeNull();
    expect(result.issue).toMatch(/effective matcher is malformed/i);
  });
});
