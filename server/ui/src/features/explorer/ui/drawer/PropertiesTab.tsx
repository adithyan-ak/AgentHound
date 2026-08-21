import { useState } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import type { APINode } from "@entities/graph/dto";
import { Grid } from "@shared/ui/layout";

const HIDDEN_KEYS = new Set([
  "objectid",
  "scan_id",
  "last_seen",
  "created_at",
  "description_hash",
  "card_hash",
]);

export function PropertiesTab({ node }: { node: APINode }) {
  const isCredential = node.kinds.includes("Credential");
  const isInstruction = node.kinds.includes("InstructionFile");
  const entries = Object.entries(node.properties ?? {})
    .filter(
      ([k, v]) =>
        !HIDDEN_KEYS.has(k) &&
        k !== "instruction_evidence_json" &&
        v !== null &&
        v !== undefined &&
        v !== "",
    );
  if (isInstruction) {
    const summary = instructionEvidenceSummary(node.properties?.instruction_evidence_json);
    if (summary) entries.push(["instruction_evidence", summary]);
  }

  if (entries.length === 0) {
    return (
      <div className="font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
        No properties recorded.
      </div>
    );
  }

  return (
    <Grid min="14rem" gap="0.75rem 2rem">
      {entries.map(([k, v]) => (
        <div key={k} className="flex min-w-0 flex-col gap-0.5">
          <div className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
            {k.replace(/_/g, " ")}
          </div>
          {isCredential && k === "value" ? (
            <CredentialValue
              key={`${node.id}:${renderValue(v)}`}
              value={renderValue(v)}
            />
          ) : (
            <div className="truncate font-mono text-[13px] text-foreground/90">
              {renderValue(v)}
            </div>
          )}
        </div>
      ))}
    </Grid>
  );
}

function instructionEvidenceSummary(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const evidence = JSON.parse(value) as {
      verdict?: unknown;
      total_signals?: unknown;
      truncated?: unknown;
    };
    if (
      (evidence.verdict !== "clean" && evidence.verdict !== "signal" && evidence.verdict !== "poisoning") ||
      typeof evidence.total_signals !== "number"
    ) {
      return null;
    }
    return `${evidence.verdict} · ${evidence.total_signals} signal${evidence.total_signals === 1 ? "" : "s"}${evidence.truncated === true ? " · evidence truncated" : ""}`;
  } catch {
    return "invalid structured instruction evidence";
  }
}

function CredentialValue({ value }: { value: string }) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  function copyValue() {
    void navigator.clipboard.writeText(value);
    setCopied(true);
  }

  return (
    <div className="flex min-w-0 items-center gap-2">
      <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-foreground/90">
        {revealed ? value : "••••••••"}
      </span>
      <button
        type="button"
        onClick={() => setRevealed((current) => !current)}
        aria-label={revealed ? "Hide credential value" : "Reveal credential value"}
        className="inline-flex h-7 items-center gap-1 rounded-[3px] border border-border bg-black/30 px-2 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground transition-colors hover:text-foreground"
      >
        {revealed ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
        {revealed ? "Hide" : "Reveal"}
      </button>
      <button
        type="button"
        onClick={copyValue}
        aria-label="Copy credential value"
        className="inline-flex h-7 items-center gap-1 rounded-[3px] border border-border bg-black/30 px-2 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground transition-colors hover:text-foreground"
      >
        {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function renderValue(v: unknown): string {
  if (v === null || v === undefined) return "\u2014";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x) => String(x)).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
