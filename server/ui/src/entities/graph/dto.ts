// Shared graph wire types — the raw shapes returned by the graph API and
// consumed across multiple entities (node, edge, finding, explorer). These are
// the canonical DTOs; richer per-entity view-models build on top of them.
//
// NodeKind / EdgeKind and their metadata are generated from the Go source of
// truth (sdk/ingest) by `go run ./server/cmd/gengraphts`. Re-export them here
// so existing call sites keep importing kinds from "@entities/graph/dto" while
// the canonical definition lives in generated.ts.

export type {
  NodeKind,
  EdgeKind,
  LensCategory,
  CollectionStatus,
  StageState,
  AuthScheme,
  AssessmentState,
  NodeKindMeta,
  EdgeKindMeta,
} from "./generated";
export {
  NODE_KIND_META,
  EDGE_KIND_META,
  NODE_KINDS,
  EDGE_KINDS,
} from "./generated";

export interface APINode {
  id: string;
  kinds: string[];
  properties: Record<string, unknown>;
}

export interface APIEdge {
  source: string;
  target: string;
  kind: string;
  source_kind?: string;
  target_kind?: string;
  properties: Record<string, unknown>;
}
