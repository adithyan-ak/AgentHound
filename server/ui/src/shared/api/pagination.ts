export interface PageMetadata {
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
  complete: boolean;
  revision: string;
}

export interface CollectionResult<T> {
  items: T[];
  total: number;
  complete: boolean;
  revision: string | null;
  incompleteReason?: "revision-changed" | "projection-changed" | "empty-page";
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
  return value as number;
}

export function parsePageMetadata(value: unknown, path = "page"): PageMetadata {
  const page = record(value, path);
  if (typeof page.has_more !== "boolean") {
    throw new TypeError(`${path}.has_more must be a boolean`);
  }
  if (typeof page.complete !== "boolean") {
    throw new TypeError(`${path}.complete must be a boolean`);
  }
  if (typeof page.revision !== "string" || page.revision.length === 0) {
    throw new TypeError(`${path}.revision must be a non-empty string`);
  }
  return {
    offset: nonNegativeInteger(page.offset, `${path}.offset`),
    limit: nonNegativeInteger(page.limit, `${path}.limit`),
    total: nonNegativeInteger(page.total, `${path}.total`),
    hasMore: page.has_more,
    complete: page.complete,
    revision: page.revision,
  };
}
