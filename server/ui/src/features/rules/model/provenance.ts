import type { Scan } from "@entities/scan";

export interface RuleManifestEntry {
  type: string;
  id: string;
  version: number;
  semantic_sha256: string;
  source: string;
  effective_matcher?: Record<string, unknown>;
}

export interface RulesetManifest {
  digest?: string;
  entries: RuleManifestEntry[];
  load_state: string;
  errors: string[];
  authenticity: string;
}

export interface ScanRulesetProvenance {
  manifest: RulesetManifest | null;
  issue?: string;
}

export function scanRulesetProvenance(scan: Scan): ScanRulesetProvenance {
  const raw = scan.metadata?.ruleset;
  if (raw == null) {
    return {
      manifest: null,
      issue:
        "This scan predates rule provenance or did not record an effective ruleset.",
    };
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    return { manifest: null, issue: "Recorded ruleset metadata is malformed." };
  }
  const manifest = raw as Record<string, unknown>;
  if (manifest.entries != null && !Array.isArray(manifest.entries)) {
    return {
      manifest: null,
      issue: "Recorded ruleset entries are unavailable.",
    };
  }

  const entries: RuleManifestEntry[] = [];
  for (const entry of (manifest.entries ?? []) as unknown[]) {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      return {
        manifest: null,
        issue: "A recorded ruleset entry is malformed.",
      };
    }
    const value = entry as Record<string, unknown>;
    if (
      typeof value.type !== "string" ||
      typeof value.id !== "string" ||
      typeof value.version !== "number" ||
      typeof value.semantic_sha256 !== "string" ||
      typeof value.source !== "string"
    ) {
      return {
        manifest: null,
        issue: "A recorded ruleset entry is incomplete.",
      };
    }
    if (
      value.effective_matcher != null &&
      (typeof value.effective_matcher !== "object" ||
        Array.isArray(value.effective_matcher))
    ) {
      return {
        manifest: null,
        issue: "A recorded effective matcher is malformed.",
      };
    }
    entries.push({
      type: value.type,
      id: value.id,
      version: value.version,
      semantic_sha256: value.semantic_sha256,
      source: value.source,
      effective_matcher:
        value.effective_matcher == null
          ? undefined
          : (value.effective_matcher as Record<string, unknown>),
    });
  }

  const errors =
    manifest.errors == null
      ? []
      : Array.isArray(manifest.errors) &&
          manifest.errors.every((error) => typeof error === "string")
        ? (manifest.errors as string[])
        : null;
  if (errors == null) {
    return { manifest: null, issue: "Recorded ruleset errors are malformed." };
  }

  return {
    manifest: {
      digest:
        typeof manifest.digest === "string" ? manifest.digest : undefined,
      entries,
      load_state:
        typeof manifest.load_state === "string"
          ? manifest.load_state
          : "unknown",
      errors,
      authenticity:
        typeof manifest.authenticity === "string"
          ? manifest.authenticity
          : "unknown",
    },
  };
}
