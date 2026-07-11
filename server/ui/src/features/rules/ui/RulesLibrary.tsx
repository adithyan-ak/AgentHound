import { useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useRules } from "@entities/rule";
import type { RuleInfo } from "@entities/rule";
import { useScan, useScans } from "@entities/scan";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { DataStateNotice } from "@shared/ui/feedback";
import { RuleCard } from "./RuleCard";
import { RuleFilters } from "./RuleFilters";
import { scanRulesetProvenance } from "../model/provenance";

const TAG_ORDER = [
  "injection",
  "credential",
  "supply-chain",
  "sensitivity",
  "capability",
  "impersonation",
  "instruction-poisoning",
];

function groupByTag(rules: RuleInfo[]): Map<string, RuleInfo[]> {
  const grouped = new Map<string, RuleInfo[]>();
  for (const rule of rules) {
    const tag = rule.tags[0] ?? "other";
    const list = grouped.get(tag) ?? [];
    list.push(rule);
    grouped.set(tag, list);
  }
  return grouped;
}

export function RulesLibrary() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [severity, setSeverity] = useState("all");
  const [collector, setCollector] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filterParams = useMemo(() => {
    const params: { severity?: string; collector?: string } = {};
    if (severity !== "all") params.severity = severity;
    if (collector !== "all") params.collector = collector;
    return params;
  }, [severity, collector]);

  const {
    data,
    isLoading,
    isError,
    error,
    dataUpdatedAt,
  } = useRules(filterParams);
  const requestedScanId = searchParams.get("scan");
  const scansQuery = useScans(50);
  const requestedScanQuery = useScan(requestedScanId);
  const scansWithProvenance = useMemo(
    () => {
      const scans = (scansQuery.data ?? []).filter(
        (scan) => scan.metadata?.ruleset != null,
      );
      const requested = requestedScanQuery.data;
      if (
        requested?.metadata?.ruleset != null &&
        !scans.some((scan) => scan.id === requested.id)
      ) {
        return [requested, ...scans];
      }
      return scans;
    },
    [requestedScanQuery.data, scansQuery.data],
  );
  const defaultScan =
    scansWithProvenance.find(
      (scan) => scan.publication_status === "published",
    ) ?? scansWithProvenance[0];
  const selectedScan =
    (requestedScanId
      ? requestedScanQuery.data?.metadata?.ruleset != null
        ? requestedScanQuery.data
        : null
      : defaultScan) ?? null;
  const invalidRequestedScan =
    requestedScanId != null &&
    !requestedScanQuery.isLoading &&
    !requestedScanQuery.isError &&
    selectedScan == null;
  const provenance = selectedScan
    ? scanRulesetProvenance(selectedScan)
    : null;

  const grouped = useMemo(() => groupByTag(data?.rules ?? []), [data?.rules]);

  const sortedTags = useMemo(() => {
    const tags = TAG_ORDER.filter((t) => grouped.has(t));
    for (const t of grouped.keys()) {
      if (!tags.includes(t)) tags.push(t);
    }
    return tags;
  }, [grouped]);

  function handleClear() {
    setSeverity("all");
    setCollector("all");
  }

  function selectScan(scanId: string) {
    const next = new URLSearchParams(searchParams);
    if (scanId) next.set("scan", scanId);
    else next.delete("scan");
    setSearchParams(next, { replace: true });
  }

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1100px] space-y-4">
        <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Detection Engine <span className="text-primary/60">//</span> Ruleset
            </p>
            <h1 className="mt-1.5 flex items-center gap-2.5 font-mono text-2xl font-bold uppercase tracking-[0.04em] text-foreground sm:text-[26px]">
              <span className="flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/10 ring-1 ring-inset ring-primary/30">
                <ShieldCheck className="h-4 w-4 text-primary" />
              </span>
              <span className="text-primary">▸</span>
              Detection Rules
              {data && (
                <span className="font-mono text-base font-semibold tabular-nums text-muted-foreground">
                  {String(data.total).padStart(2, "0")}
                </span>
              )}
              <span className="blink-caret text-primary" aria-hidden>
                _
              </span>
            </h1>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Compare a scan's recorded effective-rule manifest with the
              server's current rule catalog.
            </p>
          </div>
          <RuleFilters
            severity={severity}
            collector={collector}
            onSeverityChange={setSeverity}
            onCollectorChange={setCollector}
            onClear={handleClear}
          />
        </header>

        <section
          aria-labelledby="rules-provenance-heading"
          className="card-elevated rounded-md p-4"
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2
                id="rules-provenance-heading"
                className="font-mono text-xs font-semibold uppercase tracking-[0.12em] text-foreground"
              >
                Scan evidence provenance
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                This manifest identifies the rule semantics recorded by the
                collector. Its digest is content identity, not a trusted
                signature.
              </p>
            </div>
            <div className="min-w-[260px]">
              <label
                htmlFor="rules-scan"
                className="mb-1 block font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground"
              >
                Evidence scan
              </label>
              <select
                id="rules-scan"
                value={selectedScan?.id ?? ""}
                onChange={(event) => selectScan(event.target.value)}
                disabled={
                  scansQuery.isLoading ||
                  requestedScanQuery.isLoading ||
                  scansWithProvenance.length === 0
                }
                className="h-8 w-full rounded-[3px] border border-border bg-black/40 px-2 font-mono text-[11px] text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-50"
              >
                {(invalidRequestedScan || requestedScanQuery.isError) && (
                  <option value="">Requested scan unavailable</option>
                )}
                {scansWithProvenance.length === 0 && (
                  <option value="">No recorded manifests</option>
                )}
                {scansWithProvenance.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.id.slice(0, 12)} · {scan.collector} ·{" "}
                    {scan.completed_at
                      ? new Date(scan.completed_at).toLocaleString()
                      : scan.status}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {scansQuery.isError && (
            <DataStateNotice
              tone={scansQuery.data ? "warning" : "error"}
              title={
                scansQuery.data
                  ? "Scan provenance list may be stale"
                  : "Scan provenance unavailable"
              }
              className="mt-3"
            >
              {scansQuery.error instanceof Error
                ? scansQuery.error.message
                : "The scan-history request failed."}
            </DataStateNotice>
          )}
          {requestedScanId && requestedScanQuery.isError && (
            <DataStateNotice
              tone="error"
              title="Requested scan provenance unavailable"
              className="mt-3"
            >
              {requestedScanQuery.error instanceof Error
                ? requestedScanQuery.error.message
                : `Scan ${requestedScanId} could not be loaded.`}
            </DataStateNotice>
          )}
          {invalidRequestedScan && (
            <DataStateNotice
              tone="warning"
              title="Requested scan provenance unavailable"
              className="mt-3"
            >
              Scan {requestedScanId} has no recorded ruleset manifest.
            </DataStateNotice>
          )}
          {!scansQuery.isLoading &&
            !scansQuery.isError &&
            !requestedScanQuery.isLoading &&
            scansWithProvenance.length === 0 && (
              <DataStateNotice
                tone="warning"
                title="No scan-specific ruleset recorded"
                className="mt-3"
              >
                Legacy scans without manifest metadata cannot be attributed to
                the server's current rules.
              </DataStateNotice>
            )}
          {selectedScan && provenance?.issue && (
            <DataStateNotice
              tone="warning"
              title="Ruleset provenance incomplete"
              className="mt-3"
            >
              {provenance.issue}
            </DataStateNotice>
          )}
          {selectedScan && provenance?.manifest && (
            <div className="mt-3 rounded-[3px] border border-border bg-black/25 p-3">
              <div className="grid gap-2 font-mono text-[10px] sm:grid-cols-4">
                <div>
                  <span className="block uppercase tracking-[0.08em] text-muted-foreground">
                    Scan
                  </span>
                  <span className="text-foreground">
                    {selectedScan.id.slice(0, 12)}
                  </span>
                </div>
                <div>
                  <span className="block uppercase tracking-[0.08em] text-muted-foreground">
                    Load state
                  </span>
                  <span className="text-foreground">
                    {provenance.manifest.load_state}
                  </span>
                </div>
                <div>
                  <span className="block uppercase tracking-[0.08em] text-muted-foreground">
                    Authenticity
                  </span>
                  <span className="text-amber-200">
                    {provenance.manifest.authenticity}
                  </span>
                </div>
                <div>
                  <span className="block uppercase tracking-[0.08em] text-muted-foreground">
                    Entries
                  </span>
                  <span className="text-foreground">
                    {provenance.manifest.entries.length}
                  </span>
                </div>
              </div>
              {provenance.manifest.digest && (
                <p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">
                  digest{" "}
                  <span className="text-foreground/80">
                    {provenance.manifest.digest}
                  </span>
                </p>
              )}
              <details className="mt-3">
                <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-[0.08em] text-primary">
                  Show recorded rule entries
                </summary>
                <ul className="mt-2 max-h-64 space-y-1 overflow-auto">
                  {provenance.manifest.entries.map((entry) => (
                    <li
                      key={`${entry.type}:${entry.id}:${entry.version}`}
                      className="rounded-[2px] border border-border/60 bg-black/20 px-2 py-1.5 font-mono text-[10px]"
                    >
                      <div className="grid gap-1 sm:grid-cols-[1fr_auto_auto]">
                        <span className="text-foreground">
                          {entry.id}@{entry.version}
                        </span>
                        <span className="text-muted-foreground">
                          {entry.type} · {entry.source}
                        </span>
                        <span
                          className="max-w-[180px] truncate text-muted-foreground"
                          title={entry.semantic_sha256}
                        >
                          {entry.semantic_sha256}
                        </span>
                      </div>
                      {entry.effective_matcher ? (
                        <details className="mt-1.5 border-t border-border/50 pt-1.5">
                          <summary className="cursor-pointer uppercase tracking-[0.08em] text-primary">
                            Effective matcher definition
                          </summary>
                          <pre className="mt-1.5 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-[2px] bg-black/35 p-2 text-[10px] leading-relaxed text-foreground/80">
                            {JSON.stringify(entry.effective_matcher, null, 2)}
                          </pre>
                        </details>
                      ) : (
                        <p className="mt-1.5 border-t border-border/50 pt-1.5 text-muted-foreground">
                          Effective matcher definition unavailable in this
                          legacy manifest.
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </details>
              {provenance.manifest.errors.length > 0 && (
                <ul className="mt-2 list-disc pl-4 text-xs text-amber-200">
                  {provenance.manifest.errors.map((manifestError) => (
                    <li key={manifestError}>{manifestError}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>

        <div>
          <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.12em] text-foreground">
            Current server catalog
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Expandable matcher details below describe the server's current
            built-in/custom configuration and may differ from the selected
            scan.
          </p>
        </div>

        {isError && data && (
          <DataStateNotice tone="warning" title="Showing cached rule catalog">
            Refresh failed. This catalog was loaded{" "}
            {new Date(dataUpdatedAt).toLocaleString()} and may be stale.
          </DataStateNotice>
        )}

        {isLoading ? (
          <div className="space-y-4">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-3 w-32 rounded-[2px]" />
                <Skeleton className="h-14 w-full rounded-[3px]" />
                <Skeleton className="h-14 w-full rounded-[3px]" />
              </div>
            ))}
          </div>
        ) : isError && !data ? (
          <DataStateNotice tone="error" title="Current rule catalog unavailable">
            {error instanceof Error
              ? error.message
              : "The current rule-catalog request failed."}
          </DataStateNotice>
        ) : data?.rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-[4px] bg-primary/10 ring-1 ring-inset ring-primary/20">
              <ShieldCheck className="h-6 w-6 text-primary" />
            </span>
            <p className="font-mono text-xs uppercase tracking-[0.12em] text-muted-foreground">
              No rules match the selected filters
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {sortedTags.map((tag) => {
              const rules = grouped.get(tag) ?? [];
              return (
                <div key={tag}>
                  <div className="mb-2.5 flex items-center gap-2">
                    <span aria-hidden className="h-px w-6 bg-primary/50" />
                    <h3 className="font-mono text-console uppercase tracking-[0.18em] text-muted-foreground">
                      {tag}
                    </h3>
                    <span aria-hidden className="h-px flex-1 bg-border/60" />
                    <span className="font-mono text-[10px] tabular-nums text-muted-foreground/70">
                      {String(rules.length).padStart(2, "0")}
                    </span>
                  </div>
                  <div className="space-y-2">
                    {rules.map((rule) => (
                      <RuleCard
                        key={rule.id}
                        rule={rule}
                        isExpanded={expandedId === rule.id}
                        onToggle={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
