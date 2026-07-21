import type { APINode } from "@entities/graph/dto";

const MD_SKIP_KEYS = new Set([
  "objectid",
  "scan_id",
  "last_seen",
  "created_at",
  "description_hash",
  "card_hash",
  "previous_description_hash",
]);

const MD_PRIORITY_KEYS = [
  "name",
  "endpoint",
  "uri",
  "path",
  "hostname",
  "transport",
  "protocol_version",
  "effective_auth_method",
  "effective_auth_assurance",
  "effective_auth_evidence",
  "effective_auth_source",
  "auth_method",
  "auth_assurance",
  "auth_evidence",
  "observed_auth_method",
  "observed_auth_assurance",
  "observed_auth_evidence",
  "is_pinned",
  "scope",
  "exposure_status",
  "material_status",
  "identity_basis",
  "is_signed",
  "signature_verification_status",
  "high_entropy",
  "parameter_size",
  "has_injection_patterns",
  "has_cross_references",
  "is_suspicious",
  "sensitivity",
  "risk_score",
  "framework",
  "provider",
  "version",
  "tool_count",
  "skill_count",
  "server_count",
  "capability_surface",
];

/**
 * Format a node as a clean Markdown dump suitable for pasting into a
 * Jira ticket, GitHub issue, or incident report. Priority properties
 * (name, endpoint, effective auth, configured/observed auth, risk_score, etc.)
 * are listed first in
 * a stable order; everything else follows alphabetically. Noise fields
 * (hashes, timestamps, scan_id) are skipped.
 */
export function formatNodeAsMarkdown(
  node: APINode,
  kindTag: string,
  owned: boolean,
  highValue: boolean,
): string {
  const props = node.properties ?? {};
  const name =
    (typeof props.name === "string" && props.name) ||
    (typeof props.uri === "string" && props.uri) ||
    (typeof props.path === "string" && props.path) ||
    node.id.slice(0, 12);

  const lines: string[] = [];
  lines.push(`## ${name}`);
  lines.push("");
  lines.push(`**Kind:** ${kindTag.replace(/\s+/g, " ")}`);
  lines.push(`**Objectid:** \`${node.id}\``);

  const marks: string[] = [];
  if (owned) marks.push("🎯 Owned");
  if (highValue) marks.push("👑 High Value");
  if (marks.length > 0) {
    lines.push(`**Marked:** ${marks.join(" · ")}`);
  }

  lines.push("");
  lines.push("**Properties:**");

  const seen = new Set<string>();
  const bullets: string[] = [];

  for (const key of MD_PRIORITY_KEYS) {
    if (MD_SKIP_KEYS.has(key)) continue;
    if (!(key in props)) continue;
    const value = props[key];
    if (value === null || value === undefined || value === "") continue;
    seen.add(key);
    bullets.push(`- \`${key}\`: ${formatValue(value)}`);
  }

  const remaining = Object.keys(props)
    .filter((k) => !MD_SKIP_KEYS.has(k) && !seen.has(k))
    .sort();
  for (const key of remaining) {
    const value = props[key];
    if (value === null || value === undefined || value === "") continue;
    bullets.push(`- \`${key}\`: ${formatValue(value)}`);
  }

  if (bullets.length === 0) {
    lines.push("_(no properties recorded)_");
  } else {
    lines.push(...bullets);
  }

  lines.push("");
  lines.push("_Exported from AgentHound Explorer_");
  return lines.join("\n");
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "`true`" : "`false`";
  if (typeof v === "number") return `\`${v}\``;
  if (typeof v === "string") {
    // Wrap multi-line strings in a fenced block so tickets render them cleanly.
    if (v.includes("\n")) return `\n\n  \`\`\`\n  ${v.replace(/\n/g, "\n  ")}\n  \`\`\``;
    return v;
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return "_(empty)_";
    return v.map((x) => `\`${String(x)}\``).join(", ");
  }
  if (typeof v === "object") {
    try {
      return `\`${JSON.stringify(v)}\``;
    } catch {
      return String(v);
    }
  }
  return String(v);
}
