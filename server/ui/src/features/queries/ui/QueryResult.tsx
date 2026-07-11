import type { PreBuiltQuery } from "@entities/prebuilt/api";

interface QueryResultProps {
  rows: Record<string, unknown>[];
  query: PreBuiltQuery;
}

function isStructuredValue(value: unknown): value is object {
  return value !== null && typeof value === "object";
}

function formatScalar(value: unknown): string {
  if (value == null) return "\u2014";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function formatStructured(value: object): string {
  return JSON.stringify(value, null, 2) ?? "\u2014";
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
                  scope="col"
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
                {columns.map((col) => {
                  const value = row[col];
                  const structured = isStructuredValue(value);
                  return (
                    <td
                      key={col}
                      className={
                        structured
                          ? "max-w-[48rem] align-top px-3 py-1.5 font-mono text-[11px] text-foreground/90"
                          : "max-w-[300px] truncate whitespace-nowrap px-3 py-1.5 font-mono text-[11px] text-foreground/90"
                      }
                    >
                      {structured ? (
                        <pre className="m-0 whitespace-pre-wrap break-words font-mono text-[11px]">
                          {formatStructured(value)}
                        </pre>
                      ) : (
                        formatScalar(value)
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
