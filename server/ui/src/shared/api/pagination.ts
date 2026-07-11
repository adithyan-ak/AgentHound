export interface PageMetadata {
  offset: number;
  total: number;
  hasMore: boolean;
  complete: boolean;
  revision: string | null;
  supported: boolean;
}

export interface CollectionResult<T> {
  items: T[];
  total: number;
  complete: boolean;
  revision: string | null;
  incompleteReason?: "metadata-missing" | "revision-changed" | "empty-page";
}

function nonNegativeInteger(value: string | null): number | null {
  if (value == null || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

export function pageMetadata(
  headers: Headers,
  requestedOffset: number,
  itemCount: number,
): PageMetadata {
  const offset = nonNegativeInteger(headers.get("X-Offset"));
  const total = nonNegativeInteger(headers.get("X-Total-Count"));
  const hasMoreHeader = headers.get("X-Has-More");
  const completeHeader = headers.get("X-Collection-Complete");
  const revision = headers.get("X-Revision");
  const supported =
    offset !== null &&
    total !== null &&
    (hasMoreHeader === "true" || hasMoreHeader === "false") &&
    (completeHeader === "true" || completeHeader === "false") &&
    revision !== null;

  if (!supported) {
    return {
      offset: requestedOffset,
      total: requestedOffset + itemCount,
      hasMore: false,
      complete: false,
      revision: null,
      supported: false,
    };
  }

  return {
    offset,
    total,
    hasMore: hasMoreHeader === "true",
    complete: completeHeader === "true",
    revision,
    supported: true,
  };
}
