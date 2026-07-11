import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  EDGE_KINDS,
  parseAPIEdges,
  type EdgeKind,
} from "./dto";
import {
  EDGE_CATEGORY_MAP,
  EDGE_COMPOSITE_MAP,
} from "@entities/edge/styles";
import {
  EDGE_DESCRIPTION,
  EDGE_EXPLOIT,
} from "@entities/edge/semantics";

const goKinds = readFileSync(
  resolve(process.cwd(), "../../sdk/ingest/kinds.go"),
  "utf8",
);

function goMapKeys(name: string): string[] {
  const body = goKinds.match(
    new RegExp(`var ${name} = map\\[string\\]bool\\{([\\s\\S]*?)\\n\\}`),
  )?.[1];
  if (!body) throw new Error(`${name} map not found in sdk/ingest/kinds.go`);
  return Array.from(body.matchAll(/"([A-Z_]+)"\s*:\s*true/g), (match) =>
    String(match[1]),
  ).sort();
}

describe("Go and TypeScript edge contract parity", () => {
  it("matches every backend edge kind", () => {
    expect([...EDGE_KINDS].sort()).toEqual(goMapKeys("AllowedEdgeKinds"));
  });

  it("matches backend raw/composite classification", () => {
    const raw = new Set(goMapKeys("RawEdgeKinds"));
    for (const kind of EDGE_KINDS) {
      expect(EDGE_COMPOSITE_MAP[kind]).toBe(!raw.has(kind));
    }
  });

  it("has exhaustive semantics and category registries", () => {
    for (const kind of EDGE_KINDS) {
      expect(EDGE_CATEGORY_MAP[kind]).toBeDefined();
      expect(EDGE_DESCRIPTION[kind].length).toBeGreaterThan(0);
      expect(Object.prototype.hasOwnProperty.call(EDGE_EXPLOIT, kind)).toBe(
        true,
      );
    }
  });
});

describe("runtime edge decoding", () => {
  it("normalizes nullish collections but rejects malformed non-arrays", () => {
    expect(parseAPIEdges(null)).toEqual([]);
    expect(() => parseAPIEdges({})).toThrow(/must be an array/);
  });

  it("rejects backend kinds outside the exhaustive runtime contract", () => {
    expect(() =>
      parseAPIEdges([
        {
          source: "a",
          target: "b",
          kind: "UNKNOWN_EDGE" as EdgeKind,
          properties: {},
        },
      ]),
    ).toThrow(/supported edge kind/);
  });
});
