import {
  Table,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";

interface NodePropertiesProps {
  properties: Record<string, unknown>;
}

function formatValue(value: unknown): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (value == null) return "-";
  if (Array.isArray(value)) return value.join(", ") || "-";
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return new Date(value).toLocaleString();
  }
  return String(value);
}

export function NodeProperties({ properties }: NodePropertiesProps) {
  const entries = Object.entries(properties).filter(
    ([key]) => !key.startsWith("_"),
  );

  if (entries.length === 0) {
    return (
      <div className="py-4 text-sm text-muted-foreground text-center">
        No properties
      </div>
    );
  }

  return (
    <Table>
      <TableBody>
        {entries.map(([key, value]) => (
          <TableRow key={key}>
            <TableCell className="text-xs text-muted-foreground font-mono py-1.5 px-1">
              {key}
            </TableCell>
            <TableCell className="text-xs text-foreground text-right break-all py-1.5 px-1">
              {formatValue(value)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
