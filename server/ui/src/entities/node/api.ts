import { api } from "@shared/api/client";
import {
  parseAPIEdges,
  parseAPINodes,
  type APIEdge,
  type APINode,
} from "@entities/graph/dto";
import {
  pageMetadata,
  type CollectionResult,
} from "@shared/api/pagination";

interface NodePage {
  items: APINode[];
  metadata: ReturnType<typeof pageMetadata>;
  revisionConflict: boolean;
}

async function fetchNodePage(
  kind?: string,
  limit = 10000,
  offset = 0,
  revision?: string,
): Promise<NodePage> {
  const params: Record<string, string> = {
    limit: String(limit),
    offset: String(offset),
  };
  if (kind) params["kind"] = kind;
  if (revision) params["revision"] = revision;
  const response = await api.get("graph/nodes", {
    searchParams: params,
    throwHttpErrors: false,
  });
  if (response.status === 409) {
    return {
      items: [],
      metadata: pageMetadata(response.headers, offset, 0),
      revisionConflict: true,
    };
  }
  if (!response.ok) {
    throw new Error(`node page request failed with status ${response.status}`);
  }
  const items = parseAPINodes(await response.json<unknown>());
  return {
    items,
    metadata: pageMetadata(response.headers, offset, items.length),
    revisionConflict: false,
  };
}

export async function fetchNodeCollection(
  kind?: string,
  pageSize = 10000,
  expectedRevision?: string,
): Promise<CollectionResult<APINode>> {
  const items: APINode[] = [];
  let offset = 0;
  let revision = expectedRevision ?? null;
  let total = 0;

  for (;;) {
    const page = await fetchNodePage(
      kind,
      pageSize,
      offset,
      revision ?? undefined,
    );
    if (page.revisionConflict) {
      return {
        items,
        total,
        complete: false,
        revision,
        incompleteReason: "revision-changed",
      };
    }
    if (!page.metadata.supported) {
      return {
        items: [...items, ...page.items],
        total: items.length + page.items.length,
        complete: false,
        revision,
        incompleteReason: "metadata-missing",
      };
    }
    if (page.metadata.offset !== offset) {
      return {
        items,
        total,
        complete: false,
        revision,
        incompleteReason: "metadata-missing",
      };
    }
    if (revision !== null && page.metadata.revision !== revision) {
      return {
        items,
        total,
        complete: false,
        revision,
        incompleteReason: "revision-changed",
      };
    }
    revision = page.metadata.revision;
    total = page.metadata.total;
    items.push(...page.items);

    if (!page.metadata.hasMore) {
      return {
        items,
        total,
        complete: page.metadata.complete && items.length === total,
        revision,
      };
    }
    if (page.items.length === 0) {
      return {
        items,
        total,
        complete: false,
        revision,
        incompleteReason: "empty-page",
      };
    }
    offset += page.items.length;
  }
}

export async function fetchNodes(
  kind?: string,
  pageSize = 10000,
): Promise<APINode[]> {
  const result = await fetchNodeCollection(kind, pageSize);
  if (!result.complete) {
    throw new Error(
      `node collection incomplete: ${result.incompleteReason ?? "count mismatch"}`,
    );
  }
  return result.items;
}

export async function fetchNode(
  id: string,
): Promise<{ node: APINode; edges: APIEdge[] }> {
  const result = await api
    .get(`graph/nodes/${encodeURIComponent(id)}`)
    .json<unknown>();
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError("node detail must be an object");
  }
  const raw = result as Record<string, unknown>;
  const node = parseAPINodes([raw.node])[0];
  if (!node) throw new TypeError("node detail is missing node");
  return { node, edges: parseAPIEdges(raw.edges) };
}

export interface BlastRadiusResponse {
  nodes: APINode[];
  edges: APIEdge[];
  rings: Record<string, string[]>;
  direction: "out" | "in" | "both";
  max_hops: number;
}

export interface BlastRadiusOptions {
  direction?: "out" | "in" | "both";
  maxHops?: number;
}

export async function fetchBlastRadius(
  nodeId: string,
  opts: BlastRadiusOptions = {},
): Promise<BlastRadiusResponse> {
  const params: Record<string, string> = {};
  if (opts.direction) params["direction"] = opts.direction;
  if (opts.maxHops) params["max_hops"] = String(opts.maxHops);
  const result = await api
    .get(`graph/nodes/${encodeURIComponent(nodeId)}/blast-radius`, {
      searchParams: params,
    })
    .json<unknown>();
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError("blast-radius response must be an object");
  }
  const raw = result as Record<string, unknown>;
  if (
    raw.direction !== "out" &&
    raw.direction !== "in" &&
    raw.direction !== "both"
  ) {
    throw new TypeError("blast-radius direction is invalid");
  }
  if (typeof raw.max_hops !== "number") {
    throw new TypeError("blast-radius max_hops must be a number");
  }
  if (
    raw.rings == null ||
    typeof raw.rings !== "object" ||
    Array.isArray(raw.rings)
  ) {
    throw new TypeError("blast-radius rings must be an object");
  }
  const rings: Record<string, string[]> = {};
  for (const [hop, ids] of Object.entries(raw.rings)) {
    if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string")) {
      throw new TypeError(`blast-radius rings.${hop} must be a string array`);
    }
    rings[hop] = ids;
  }
  return {
    nodes: parseAPINodes(raw.nodes),
    edges: parseAPIEdges(raw.edges),
    rings,
    direction: raw.direction,
    max_hops: raw.max_hops,
  };
}
