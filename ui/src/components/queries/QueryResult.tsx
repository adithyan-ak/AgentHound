import type { PreBuiltQuery } from "@/api/types";

interface QueryResultProps {
  rows: Record<string, unknown>[];
  query: PreBuiltQuery;
}

function formatCell(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.join(", ") || "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function QueryResult({ rows, query }: QueryResultProps) {
  if (rows.length === 0) {
    return (
      <div className="py-4 text-sm text-zinc-500 text-center">
        No results for "{query.name}"
      </div>
    );
  }

  const columns = Object.keys(rows[0]!);

  return (
    <div>
      <div className="text-xs text-zinc-400 mb-2">
        {rows.length} row{rows.length !== 1 ? "s" : ""}
      </div>
      <div className="overflow-x-auto rounded-md border border-zinc-700">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 bg-zinc-800/50">
              {columns.map((col) => (
                <th
                  key={col}
                  className="px-3 py-1.5 text-left text-xs font-medium text-zinc-400"
                >
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-700/50">
            {rows.map((row, i) => (
              <tr key={i} className="hover:bg-zinc-800/30">
                {columns.map((col) => (
                  <td
                    key={col}
                    className="px-3 py-1.5 text-xs text-zinc-300 max-w-[300px] truncate"
                  >
                    {formatCell(row[col])}
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
