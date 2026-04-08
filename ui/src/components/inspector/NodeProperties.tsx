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
      <div className="py-4 text-sm text-zinc-500 text-center">
        No properties
      </div>
    );
  }

  return (
    <div className="divide-y divide-zinc-700/50">
      {entries.map(([key, value]) => (
        <div key={key} className="flex justify-between gap-4 py-1.5 px-1">
          <span className="text-xs text-zinc-400 font-mono flex-shrink-0">
            {key}
          </span>
          <span className="text-xs text-zinc-200 text-right break-all">
            {formatValue(value)}
          </span>
        </div>
      ))}
    </div>
  );
}
