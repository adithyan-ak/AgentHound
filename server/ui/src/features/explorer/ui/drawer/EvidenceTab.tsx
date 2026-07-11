import type { APINode } from "@entities/graph/dto";

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
  "probe_status",
  "configuration_observed",
  "configured_via",
  "configured_auth_method",
  "assertion_type",
  "confidence_scope",
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
  const observation =
    props.probe_status === "verified"
      ? {
          title: "Directly verified",
          detail:
            "A direct probe verified this entity at collection time.",
          className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
        }
      : props.configuration_observed === true ||
          props.probe_status === "configured_unverified"
        ? {
            title: "Configured, not verified",
            detail:
              "AgentHound observed a configuration reference. Service availability and authentication were not directly verified.",
            className: "border-amber-400/30 bg-amber-400/10 text-amber-200",
          }
        : props.probe_status === "failed"
          ? {
              title: "Verification failed",
              detail:
                "A direct verification attempt failed; configuration presence does not establish current availability.",
              className:
                "border-destructive/30 bg-destructive/10 text-destructive",
            }
          : {
              title: "Verification status unknown",
              detail:
                "No direct verification status was recorded. Do not infer availability or absence from this node alone.",
              className: "border-border bg-black/30 text-muted-foreground",
            };

  return (
    <div className="space-y-5">
      <div className={`rounded-[3px] border p-3 ${observation.className}`}>
        <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em]">
          {observation.title}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
          {observation.detail}
        </p>
      </div>
      <div>
        <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          Identity
        </div>
        <div className="rounded-[3px] border border-border bg-black/40 p-3 font-mono text-[11px] text-foreground/90">
          <div>
            <span className="text-muted-foreground">objectid </span>
            {objectId}
          </div>
          {scanId && (
            <div>
              <span className="text-muted-foreground">scan_id </span>
              {scanId}
            </div>
          )}
          {createdAt && (
            <div>
              <span className="text-muted-foreground">created_at </span>
              {createdAt}
            </div>
          )}
          {lastSeen && (
            <div>
              <span className="text-muted-foreground">last_seen </span>
              {lastSeen}
            </div>
          )}
        </div>
      </div>

      {rawEvidence.map(({ key, value }) => (
        <div key={key}>
          <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
            {key.replace(/_/g, " ")}
          </div>
          <pre className="max-h-[240px] overflow-auto whitespace-pre-wrap break-words rounded-[3px] border border-border bg-black/40 p-3 font-mono text-[11px] text-foreground/90">
            {formatEvidence(value)}
          </pre>
        </div>
      ))}

      {rawEvidence.length === 0 && (
        <div className="font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
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
