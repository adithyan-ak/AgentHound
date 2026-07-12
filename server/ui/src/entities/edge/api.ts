import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";
import {
  parseAPIEdges,
  parseProjectionIdentity,
  sameProjectionIdentity,
  type APIEdge,
  type ProjectionIdentity,
} from "@entities/graph/dto";
import {
  parsePageMetadata,
  type PageMetadata,
  type CollectionResult,
} from "@shared/api/pagination";
import { ProjectionConflictError } from "@shared/api/conflicts";

interface EdgePage {
  items: APIEdge[];
  metadata?: PageMetadata;
  projection?: ProjectionIdentity;
  revisionConflict: boolean;
  conflictRevision?: string;
}

export interface EdgeCollectionResult extends CollectionResult<APIEdge> {
  projection: ProjectionIdentity | null;
}

async function fetchEdgePage(
  kind?: string,
  limit = 100000,
  offset = 0,
  revision?: string,
): Promise<EdgePage> {
  const params: Record<string, string> = {
    limit: String(limit),
    offset: String(offset),
  };
  if (kind) params["kind"] = kind;
  if (revision) params["revision"] = revision;
  const response = await api.get("graph/edges", {
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
      throw new Error("edge page request conflicted");
    }
    return {
      items: [],
      revisionConflict: true,
      conflictRevision: conflictRevision(error),
    };
  }
  if (!response.ok) {
    throw new Error(`edge page request failed with status ${response.status}`);
  }
  const envelope = record(await response.json<unknown>(), "edge list");
  const items = parseAPIEdges(envelope.edges);
  const page = record(envelope.page, "edge list.page");
  return {
    items,
    metadata: parsePageMetadata(page, "edge list.page"),
    projection: parseProjectionIdentity(
      page.projection,
      "edge list.page.projection",
    ),
    revisionConflict: false,
  };
}

export async function fetchEdgeCollection(
  kind?: string,
  pageSize = 100000,
  expectedRevision?: string,
): Promise<EdgeCollectionResult> {
  const items: APIEdge[] = [];
  let offset = 0;
  let revision = expectedRevision ?? null;
  let projection: ProjectionIdentity | null = null;
  let total = 0;

  for (;;) {
    const page = await fetchEdgePage(
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
      throw new TypeError("edge list.page is required");
    }
    if (metadata.offset !== offset) {
      throw new TypeError("edge list.page.offset does not match the requested offset");
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
      throw new TypeError("edge list.page.projection is required");
    }
    if (
      projection !== null &&
      !sameProjectionIdentity(projection, page.projection)
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

export async function fetchEdges(
  kind?: string,
  pageSize = 100000,
): Promise<APIEdge[]> {
  const result = await fetchEdgeCollection(kind, pageSize);
  if (!result.complete) {
    throw new Error(
      `edge collection incomplete: ${result.incompleteReason ?? "count mismatch"}`,
    );
  }
  return result.items;
}

// Single "all edges" cache (the inspector pulls the full set and filters
// client-side). `enabled` gates the fetch when there is nothing to inspect.
export function useEdges(enabled = true) {
  const query = useQuery({
    queryKey: qk.edges(),
    queryFn: async () => {
      const result = await fetchEdgeCollection(undefined, 100000);
      if (!result.complete) {
        throw new Error(
          `edge collection incomplete: ${result.incompleteReason ?? "count mismatch"}`,
        );
      }
      return result;
    },
    enabled,
  });
  return {
    ...query,
    data: query.data?.items,
    snapshot: query.data?.projection,
  };
}
