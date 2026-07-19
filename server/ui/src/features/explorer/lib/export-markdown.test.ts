import { describe, expect, it } from "vitest";
import type { APINode } from "@entities/graph/dto";
import { formatNodeAsMarkdown } from "./export-markdown";

describe("formatNodeAsMarkdown authentication evidence", () => {
  it("leads with the effective tuple while retaining both raw provenance lanes", () => {
    const node: APINode = {
      id: "sha256:server",
      kinds: ["MCPServer"],
      properties: {
        name: "anonymous-runtime-server",
        auth_method: "unknown",
        auth_assurance: "unknown",
        auth_evidence: "unknown",
        observed_auth_method: "none",
        observed_auth_assurance: "unauthenticated",
        observed_auth_evidence: "anonymous_probe_succeeded",
        effective_auth_method: "none",
        effective_auth_assurance: "unauthenticated",
        effective_auth_evidence: "anonymous_probe_succeeded",
        effective_auth_source: "observed",
      },
    };

    const markdown = formatNodeAsMarkdown(node, "MCP Server", false, false);
    const effective = markdown.indexOf("`effective_auth_method`: none");
    const configured = markdown.indexOf("`auth_method`: unknown");
    const observed = markdown.indexOf("`observed_auth_method`: none");

    expect(effective).toBeGreaterThan(-1);
    expect(configured).toBeGreaterThan(effective);
    expect(observed).toBeGreaterThan(configured);
    expect(markdown).toContain(
      "`effective_auth_evidence`: anonymous_probe_succeeded",
    );
    expect(markdown).toContain("`effective_auth_source`: observed");
  });
});
