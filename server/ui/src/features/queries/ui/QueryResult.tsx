import type { ReactNode } from "react";
import type { PreBuiltQuery } from "@entities/prebuilt/api";

interface QueryResultProps {
  rows: Record<string, unknown>[];
  query: PreBuiltQuery;
}

const EM_DASH = "\u2014";

function isPrimitive(v: unknown): boolean {
  return v == null || typeof v !== "object";
}

// Recursively renders a query cell value. Cypher results routinely nest
// objects and arrays-of-objects (path node/edge collections, maps); rendering
// them as raw JSON.stringify hides structure. This walks the value and renders
// nested maps/lists as readable key/value trees instead of a JSON blob.
function CellValue({ value, depth = 0 }: { value: unknown; depth?: number }): ReactNode {
  if (value == null) return <span className="text-muted-foreground/60">{EM_DASH}</span>;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" || typeof value === "string") return String(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-muted-foreground/60">{EM_DASH}</span>;
    // Arrays of primitives read best as a comma-joined line.
    if (value.every(isPrimitive)) {
      return value.map((v) => (v == null ? EM_DASH : String(v))).join(", ");
    }
    return (
      <ul className="space-y-0.5">
        {value.map((item, i) => (
          <li key={i} className="border-l border-border/50 pl-2">
            <CellValue value={item} depth={depth + 1} />
          </li>
        ))}
      </ul>
    );
  }

  // Plain object → key: value tree.
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return <span className="text-muted-foreground/60">{"{}"}</span>;
  return (
    <ul className="space-y-0.5">
      {entries.map(([k, v]) => (
        <li key={k} className="flex gap-1.5">
          <span className="shrink-0 text-primary/70">{k}:</span>
          <span className="min-w-0">
            <CellValue value={v} depth={depth + 1} />
          </span>
        </li>
      ))}
    </ul>
  );
}

export function QueryResult({ rows, query }: QueryResultProps) {
  if (rows.length === 0) {
    return (
      <div className="py-4 text-center font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
        No results for "{query.name}"
      </div>
    );
  }

  const columns = Object.keys(rows[0]!);

  return (
    <div>
      <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
        {rows.length} row{rows.length !== 1 ? "s" : ""}
      </div>
      <div className="overflow-x-auto rounded-[3px] border border-border/70">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-border bg-black/30">
              {columns.map((col) => (
                <th
                  key={col}
                  className="px-3 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground"
                >
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr
                key={i}
                className="border-b border-border/50 transition-colors last:border-0 hover:bg-white/[0.03]"
              >
                {columns.map((col) => (
                  <td
                    key={col}
                    className="max-w-[360px] break-words px-3 py-1.5 align-top font-mono text-[11px] text-foreground/90"
                  >
                    <CellValue value={row[col]} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
