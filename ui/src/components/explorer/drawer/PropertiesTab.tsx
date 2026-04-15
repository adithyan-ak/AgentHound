import type { APINode } from "@/api/types";

const HIDDEN_KEYS = new Set([
  "objectid",
  "scan_id",
  "last_seen",
  "created_at",
  "description_hash",
  "card_hash",
]);

export function PropertiesTab({ node }: { node: APINode }) {
  const entries = Object.entries(node.properties ?? {}).filter(
    ([k, v]) => !HIDDEN_KEYS.has(k) && v !== null && v !== undefined && v !== "",
  );

  if (entries.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">No properties recorded.</div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-x-8 gap-y-3 max-w-4xl">
      {entries.map(([k, v]) => (
        <div key={k} className="flex flex-col gap-0.5 min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
            {k.replace(/_/g, " ")}
          </div>
          <div className="truncate text-[13px] text-foreground font-mono">
            {renderValue(v)}
          </div>
        </div>
      ))}
    </div>
  );
}

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x) => String(x)).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
