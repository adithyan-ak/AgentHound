import type { PreBuiltQuery } from "@/api/types";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";

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
      <div className="py-4 text-sm text-muted-foreground text-center">
        No results for "{query.name}"
      </div>
    );
  }

  const columns = Object.keys(rows[0]!);

  return (
    <div>
      <div className="text-xs text-muted-foreground mb-2">
        {rows.length} row{rows.length !== 1 ? "s" : ""}
      </div>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map((col) => (
                <TableHead key={col} className="text-xs h-8 px-3">
                  {col}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row, i) => (
              <TableRow key={i}>
                {columns.map((col) => (
                  <TableCell
                    key={col}
                    className="px-3 py-1.5 text-xs max-w-[300px] truncate"
                  >
                    {formatCell(row[col])}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
