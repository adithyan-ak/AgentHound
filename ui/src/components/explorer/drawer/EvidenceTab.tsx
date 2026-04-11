import type { APINode } from "@/api/types";

const EVIDENCE_KEYS = [
  "description",
  "instructions",
  "input_schema",
  "output_schema",
  "config_path",
  "path",
  "endpoint",
  "uri",
  "capabilities",
  "capability_surface",
  "annotations",
  "security_schemes",
  "signatures",
];

export function EvidenceTab({ node }: { node: APINode }) {
  const props = node.properties ?? {};

  const rawEvidence = EVIDENCE_KEYS.map((k) => ({
    key: k,
    value: props[k],
  })).filter(
    ({ value }) =>
      value !== null && value !== undefined && value !== "" && value !== false,
  );

  const scanId = String(props.scan_id ?? "");
  const lastSeen = String(props.last_seen ?? "");
  const createdAt = String(props.created_at ?? "");
  const objectId = node.id;

  return (
    <div className="space-y-5 max-w-4xl">
      <div>
        <div className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
          Identity
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-900/40 p-3 font-mono text-[11px] text-slate-300">
          <div>
            <span className="text-slate-500">objectid </span>
            {objectId}
          </div>
          {scanId && (
            <div>
              <span className="text-slate-500">scan_id </span>
              {scanId}
            </div>
          )}
          {createdAt && (
            <div>
              <span className="text-slate-500">created_at </span>
              {createdAt}
            </div>
          )}
          {lastSeen && (
            <div>
              <span className="text-slate-500">last_seen </span>
              {lastSeen}
            </div>
          )}
        </div>
      </div>

      {rawEvidence.map(({ key, value }) => (
        <div key={key}>
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
            {key.replace(/_/g, " ")}
          </div>
          <pre className="rounded-md border border-slate-800 bg-slate-900/40 p-3 font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-words max-h-[240px] overflow-auto">
            {formatEvidence(value)}
          </pre>
        </div>
      ))}

      {rawEvidence.length === 0 && (
        <div className="text-sm text-slate-500">
          No collected evidence for this node.
        </div>
      )}
    </div>
  );
}

function formatEvidence(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
