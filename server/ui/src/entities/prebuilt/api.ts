import { api } from "@shared/api/client";

export interface PreBuiltQuery {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  owasp_map?: string[];
  atlas_map?: string[];
}

export interface ProjectionIdentity {
  scanId: string;
  revision: number;
}

export interface TraversalMetadata {
  scope: "security" | "topology";
  direction: "out" | "both";
  relationshipKinds: string[];
  maxHops: number;
  algorithm: string;
  complete: boolean;
  truncated: boolean;
  expansionLimit: number;
  expansions: number;
  incompleteReason?: string;
}

export interface PreBuiltResult {
  query: PreBuiltQuery;
  rows: Record<string, unknown>[];
  projection: ProjectionIdentity;
  metadata?: TraversalMetadata;
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  return value;
}

function string(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

function integer(value: unknown, field: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new TypeError(`${field} must be an integer greater than or equal to ${minimum}`);
  }
  return value as number;
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${field} must be a boolean`);
  }
  return value;
}

function stringArray(value: unknown, field: string): string[] {
  return array(value, field).map((entry, index) =>
    string(entry, `${field}[${index}]`),
  );
}

function decodeQuery(value: unknown, field: string): PreBuiltQuery {
  const query = record(value, field);
  return {
    id: string(query.id, `${field}.id`),
    name: string(query.name, `${field}.name`),
    description: string(query.description, `${field}.description`),
    category: string(query.category, `${field}.category`),
    severity: string(query.severity, `${field}.severity`),
    ...(query.owasp_map === undefined
      ? {}
      : { owasp_map: stringArray(query.owasp_map, `${field}.owasp_map`) }),
    ...(query.atlas_map === undefined
      ? {}
      : { atlas_map: stringArray(query.atlas_map, `${field}.atlas_map`) }),
  };
}

function decodeProjection(value: unknown): ProjectionIdentity {
  const projection = record(value, "prebuilt result.projection");
  return {
    scanId: string(projection.scan_id, "prebuilt result.projection.scan_id"),
    revision: integer(
      projection.revision,
      "prebuilt result.projection.revision",
      1,
    ),
  };
}

export function decodeTraversalMetadata(value: unknown): TraversalMetadata {
  const metadata = record(value, "prebuilt result.metadata");
  if (metadata.scope !== "security" && metadata.scope !== "topology") {
    throw new TypeError("prebuilt result.metadata.scope is invalid");
  }
  if (metadata.direction !== "out" && metadata.direction !== "both") {
    throw new TypeError("prebuilt result.metadata.direction is invalid");
  }
  const incompleteReason =
    metadata.incomplete_reason === undefined
      ? undefined
      : string(
          metadata.incomplete_reason,
          "prebuilt result.metadata.incomplete_reason",
        );
  return {
    scope: metadata.scope,
    direction: metadata.direction,
    relationshipKinds: stringArray(
      metadata.relationship_kinds,
      "prebuilt result.metadata.relationship_kinds",
    ),
    maxHops: integer(metadata.max_hops, "prebuilt result.metadata.max_hops", 1),
    algorithm: string(metadata.algorithm, "prebuilt result.metadata.algorithm"),
    complete: boolean(metadata.complete, "prebuilt result.metadata.complete"),
    truncated: boolean(metadata.truncated, "prebuilt result.metadata.truncated"),
    expansionLimit: integer(
      metadata.expansion_limit,
      "prebuilt result.metadata.expansion_limit",
      1,
    ),
    expansions: integer(
      metadata.expansions,
      "prebuilt result.metadata.expansions",
    ),
    ...(incompleteReason === undefined ? {} : { incompleteReason }),
  };
}

export async function fetchPreBuiltQueries(): Promise<PreBuiltQuery[]> {
  return array(await api.get("analysis/prebuilt").json<unknown>(), "queries").map(
    (query, index) => decodeQuery(query, `queries[${index}]`),
  );
}

export async function runPreBuiltQuery(
  id: string,
): Promise<PreBuiltResult> {
  const result = await api
    .get(`analysis/prebuilt/${encodeURIComponent(id)}`)
    .json<unknown>();
  const raw = record(result, "prebuilt result");
  const query = decodeQuery(raw.query, "prebuilt result.query");
  const rows = array(raw.rows, "prebuilt result.rows").map((row, index) =>
    record(row, `prebuilt result.rows[${index}]`),
  );
  const metadata =
    raw.metadata === undefined
      ? undefined
      : decodeTraversalMetadata(raw.metadata);
  if (id === "shortest-to-database" && metadata === undefined) {
    throw new TypeError(
      "prebuilt result.metadata is required for shortest-to-database",
    );
  }
  return {
    query,
    rows,
    projection: decodeProjection(raw.projection),
    ...(metadata === undefined ? {} : { metadata }),
  };
}
