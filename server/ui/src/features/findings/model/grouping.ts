export const FINDING_GROUP_VALUES = [
  "none",
  "severity",
  "target",
  "source",
  "category",
  "owasp",
  "edge_kind",
  "triage",
] as const;

export type GroupBy = (typeof FINDING_GROUP_VALUES)[number];

export function isFindingGroup(value: string | null): value is GroupBy {
  return (
    value != null &&
    (FINDING_GROUP_VALUES as readonly string[]).includes(value)
  );
}

export function canonicalFindingGroup(value: string | null): GroupBy {
  return isFindingGroup(value) ? value : "none";
}

export function canonicalizeFindingGroupParams(
  params: URLSearchParams,
): URLSearchParams {
  const next = new URLSearchParams(params);
  const raw = next.get("group");
  if (raw != null && !isFindingGroup(raw)) {
    next.delete("group");
  }
  return next;
}
