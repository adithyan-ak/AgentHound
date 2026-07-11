import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";
import { parseAPIEdges, type APIEdge } from "@entities/graph/dto";
import {
  pageMetadata,
  type CollectionResult,
} from "@shared/api/pagination";

interface EdgePage {
  items: APIEdge[];
  metadata: ReturnType<typeof pageMetadata>;
  revisionConflict: boolean;
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
    return {
      items: [],
      metadata: pageMetadata(response.headers, offset, 0),
      revisionConflict: true,
    };
  }
  if (!response.ok) {
    throw new Error(`edge page request failed with status ${response.status}`);
  }
  const items = parseAPIEdges(await response.json<unknown>());
  return {
    items,
    metadata: pageMetadata(response.headers, offset, items.length),
    revisionConflict: false,
  };
}

export async function fetchEdgeCollection(
  kind?: string,
  pageSize = 100000,
  expectedRevision?: string,
): Promise<CollectionResult<APIEdge>> {
  const items: APIEdge[] = [];
  let offset = 0;
  let revision = expectedRevision ?? null;
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
  return useQuery({
    queryKey: qk.edges(),
    queryFn: () => fetchEdges(undefined, 100000),
    enabled,
  });
}
