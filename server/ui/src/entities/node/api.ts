import { api } from "@shared/api/client";
import {
  parseAPIEdges,
  parseAPINodes,
  parseProjectionIdentity,
  type APIEdge,
  type APINode,
  type ProjectionIdentity,
} from "@entities/graph/dto";
import {
  parsePageMetadata,
  type PageMetadata,
  type CollectionResult,
} from "@shared/api/pagination";
import { ProjectionConflictError } from "@shared/api/conflicts";

interface NodePage {
  items: APINode[];
  metadata?: PageMetadata;
  projection?: ProjectionIdentity;
  revisionConflict: boolean;
  conflictRevision?: string;
}

export interface NodeCollectionResult extends CollectionResult<APINode> {
  projection: ProjectionIdentity | null;
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
    const error = record(await response.json<unknown>(), "revision conflict");
    const detail = record(error.error, "revision conflict.error");
    if (detail.code === "PROJECTION_CONFLICT") {
      throw new ProjectionConflictError(
        typeof detail.message === "string" ? detail.message : undefined,
      );
    }
    if (detail.code !== "REVISION_CONFLICT") {
      throw new Error("node page request conflicted");
    }
    return {
      items: [],
      revisionConflict: true,
      conflictRevision: conflictRevision(error),
    };
  }
  if (!response.ok) {
    throw new Error(`node page request failed with status ${response.status}`);
  }
  const envelope = record(await response.json<unknown>(), "node list");
  const items = parseAPINodes(envelope.nodes);
  const metadata = parsePageMetadata(envelope.page, "node list.page");
  return {
    items,
    metadata,
    projection: parseProjectionIdentity(
      record(envelope.page, "node list.page").projection,
      "node list.page.projection",
    ),
    revisionConflict: false,
  };
}

export async function fetchNodeCollection(
  kind?: string,
  pageSize = 10000,
  expectedRevision?: string,
): Promise<NodeCollectionResult> {
  const items: APINode[] = [];
  let offset = 0;
  let revision = expectedRevision ?? null;
  let projection: ProjectionIdentity | null = null;
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
        revision: page.conflictRevision ?? revision,
        projection,
        incompleteReason: "revision-changed",
      };
    }
    const metadata = page.metadata;
    if (!metadata) {
      throw new TypeError("node list.page is required");
    }
    if (metadata.offset !== offset) {
      throw new TypeError("node list.page.offset does not match the requested offset");
    }
    if (revision !== null && metadata.revision !== revision) {
      return {
        items,
        total,
        complete: false,
        revision,
        projection,
        incompleteReason: "revision-changed",
      };
    }
    if (!page.projection) {
      throw new TypeError("node list.page.projection is required");
    }
    if (
      projection !== null &&
      (projection.scanId !== page.projection.scanId ||
        projection.revision !== page.projection.revision)
    ) {
      return {
        items,
        total,
        complete: false,
        revision,
        projection,
        incompleteReason: "projection-changed",
      };
    }
    projection = page.projection;
    revision = metadata.revision;
    total = metadata.total;
    items.push(...page.items);

    if (!metadata.hasMore) {
      return {
        items,
        total,
        complete: metadata.complete && items.length === total,
        revision,
        projection,
      };
    }
    if (page.items.length === 0) {
      return {
        items,
        total,
        complete: false,
        revision,
        projection,
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

function record(value: unknown, path: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function conflictRevision(envelope: Record<string, unknown>): string {
  const error = record(envelope.error, "revision conflict.error");
  const details = record(error.details, "revision conflict.error.details");
  if (
    typeof details.actual_revision !== "string" ||
    details.actual_revision.length === 0
  ) {
    throw new TypeError(
      "revision conflict.error.details.actual_revision must be a non-empty string",
    );
  }
  return details.actual_revision;
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
