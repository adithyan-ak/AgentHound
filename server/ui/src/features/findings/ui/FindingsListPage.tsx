import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ChevronsUpDown,
  Copy,
  Check,
  GitBranchPlus,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  X,
} from "lucide-react";
import {
  isCurrentPublishedFindingScope,
  useFindings,
  useSetTriage,
  SEVERITY_RANK,
} from "@entities/finding";
import type { Finding } from "@entities/finding/model";
import { edgeLabel } from "@entities/edge";
import {
  TRIAGE_ORDER,
  TRIAGE_META,
  type TriageStatus,
} from "@shared/model/triage";
import { buildFindingsTableMarkdown } from "../lib/copy-report";
import {
  canonicalFindingGroup,
  canonicalizeFindingGroupParams,
  isFindingGroup,
  type GroupBy,
} from "../model/grouping";
import { isEditableTarget } from "@shared/lib";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { DataStateNotice } from "@shared/ui/feedback";
import { MiniHexIcon } from "./MiniHexIcon";
import { WidgetCard } from "@shared/ui/widgets";
import { Sidebar } from "@shared/ui/layout";
import { cn } from "@shared/lib/utils";
import {
  ACCENT,
  SEVERITY,
  SEVERITY_BY_KEY,
  severityColor,
  XPROTO_ACCENT,
} from "@shared/theme/tokens";

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

type SortKey = "severity" | "confidence" | "category" | "title";
type SortDir = "asc" | "desc";

// Short labels — these now render as facet pills in the rail, not a <select>.
const GROUP_OPTIONS: Array<{ value: GroupBy; label: string }> = [
  { value: "none", label: "None" },
  { value: "severity", label: "Severity" },
  { value: "target", label: "Target" },
  { value: "source", label: "Source" },
  { value: "category", label: "Category" },
  { value: "owasp", label: "OWASP" },
  { value: "edge_kind", label: "Relationship" },
  { value: "triage", label: "Triage" },
];

const CONF_OPTIONS = [0, 50, 75, 90];

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

const A2A = (k: string) => k.startsWith("A2A");
const MCP = (k: string) => k.startsWith("MCP");
function isCrossProtocol(f: Finding): boolean {
  return (
    (A2A(f.source_kind) && MCP(f.target_kind)) ||
    (MCP(f.source_kind) && A2A(f.target_kind))
  );
}

const DEFAULT_DIR: Record<SortKey, SortDir> = {
  severity: "asc",
  confidence: "desc",
  category: "asc",
  title: "asc",
};

export function FindingsListPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const showSuppressed = params.get("suppressed") === "1";
  const {
    data: findings,
    snapshot,
    isLoading,
    isError,
    dataUpdatedAt,
  } = useFindings(showSuppressed);
  const setTriage = useSetTriage();

  // Triage status now arrives inline on each finding (server-backed). Derive
  // the id→status lookup the filter/sort/group paths use from that, so they
  // stay in sync without a separate store.
  const triageMap = useMemo(() => {
    const m: Record<string, TriageStatus> = {};
    for (const f of findings ?? []) {
      if (f.triage?.status) m[f.id] = f.triage.status as TriageStatus;
    }
    return m;
  }, [findings]);

  const searchRef = useRef<HTMLInputElement | null>(null);
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([]);

  // --- filter state lives in the URL (shareable / bookmarkable) ---
  const search = params.get("q") ?? "";
  const activeSeverities = useMemo(
    () => new Set((params.get("sev") ?? "").split(",").filter(Boolean)),
    [params],
  );
  const activeTriage = useMemo(
    () => new Set((params.get("triage") ?? "").split(",").filter(Boolean)),
    [params],
  );
  const rawGroup = params.get("group");
  const groupBy = canonicalFindingGroup(rawGroup);
  const xproto = params.get("xproto") === "1";
  const minConf = Number(params.get("conf") ?? 0);

  // --- ephemeral local state ---
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({
    key: "severity",
    dir: "asc",
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [cursor, setCursor] = useState(0);
  const [copied, setCopied] = useState(false);
  const [railOpen, setRailOpen] = useState(true);

  function patch(updates: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(updates)) {
      if (v == null || v === "") next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  }

  useEffect(() => {
    if (rawGroup == null || isFindingGroup(rawGroup)) return;
    setParams(canonicalizeFindingGroupParams(params), { replace: true });
  }, [params, rawGroup, setParams]);

  function toggleCsv(key: string, current: Set<string>, value: string) {
    const next = new Set(current);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    patch({ [key]: Array.from(next).join(",") });
  }

  const statusOf = (id: string): TriageStatus => triageMap[id] ?? "new";

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, xproto: 0 };
    for (const f of findings ?? []) {
      if (
        f.severity === "critical" ||
        f.severity === "high" ||
        f.severity === "medium" ||
        f.severity === "low"
      ) {
        c[f.severity] += 1;
      }
      if (isCrossProtocol(f)) c.xproto += 1;
    }
    return c;
  }, [findings]);

  // Per-status totals power the STATUS facet counts in the rail.
  const triageCounts = useMemo(() => {
    const c: Record<TriageStatus, number> = {
      new: 0,
      triaging: 0,
      confirmed: 0,
      "accepted-risk": 0,
      "false-positive": 0,
    };
    for (const f of findings ?? []) c[statusOf(f.id)] += 1;
    return c;
  }, [findings, triageMap]);

  const filtered = useMemo(() => {
    if (!findings) return [];
    const q = search.toLowerCase();
    return findings.filter((f) => {
      if (activeSeverities.size > 0 && !activeSeverities.has(f.severity)) return false;
      if (activeTriage.size > 0 && !activeTriage.has(statusOf(f.id))) return false;
      if (xproto && !isCrossProtocol(f)) return false;
      if (minConf > 0 && f.confidence * 100 < minConf) return false;
      if (q) {
        return (
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.source_name.toLowerCase().includes(q) ||
          f.target_name.toLowerCase().includes(q) ||
          f.edge_kind.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, search, activeSeverities, activeTriage, xproto, minConf, triageMap]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    const factor = sort.dir === "asc" ? 1 : -1;
    arr.sort((a, b) => {
      let r = 0;
      switch (sort.key) {
        case "severity":
          r = (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4);
          break;
        case "confidence":
          r = a.confidence - b.confidence;
          break;
        case "category":
          r = a.category.localeCompare(b.category);
          break;
        case "title":
          r = a.title.localeCompare(b.title);
          break;
      }
      if (r === 0) r = b.confidence - a.confidence;
      return r * factor;
    });
    return arr;
  }, [filtered, sort, triageMap]);

  // Grouping → ordered sections + a flat ordered list for keyboard nav.
  const { groups, ordered } = useMemo(() => {
    if (groupBy === "none") {
      return { groups: null as null | Array<[string, Finding[]]>, ordered: sorted };
    }
    const map = new Map<string, Finding[]>();
    for (const f of sorted) {
      const label =
        groupBy === "severity"
          ? f.severity
          : groupBy === "target"
            ? f.target_name || f.target_id.slice(0, 12)
            : groupBy === "source"
              ? f.source_name || f.source_id.slice(0, 12)
              : groupBy === "category"
                ? f.category || "—"
                : groupBy === "owasp"
                  ? f.owasp_map[0] ?? "—"
                  : groupBy === "edge_kind"
                    ? f.edge_kind
                    : statusOf(f.id);
      const list = map.get(label) ?? [];
      list.push(f);
      map.set(label, list);
    }
    let entries = Array.from(map.entries());
    if (groupBy === "severity") {
      entries = entries.sort(
        (a, b) => (SEVERITY_RANK[a[0]] ?? 4) - (SEVERITY_RANK[b[0]] ?? 4),
      );
    } else if (groupBy === "triage") {
      entries = entries.sort(
        (a, b) =>
          TRIAGE_ORDER.indexOf(a[0] as TriageStatus) -
          TRIAGE_ORDER.indexOf(b[0] as TriageStatus),
      );
    }
    return { groups: entries, ordered: entries.flatMap(([, list]) => list) };
  }, [sorted, groupBy, triageMap]);

  const total = findings?.length ?? 0;
  const hasCachedFindings = findings !== undefined;
  const coldError = isError && !hasCachedFindings;
  const cachedRefreshError = isError && hasCachedFindings;
  const scopeUnavailable =
    hasCachedFindings && snapshot?.available !== true;
  const scopeStale =
    hasCachedFindings &&
    snapshot?.available === true &&
    !isCurrentPublishedFindingScope(snapshot);
  const canClaimCurrent =
    !isError && isCurrentPublishedFindingScope(snapshot);
  const canShowSnapshotCounts =
    hasCachedFindings && snapshot?.available === true;

  // Number of *secondary* filters active (everything that lives in the rail).
  const activeFacetCount =
    (activeTriage.size > 0 ? 1 : 0) +
    (minConf > 0 ? 1 : 0) +
    (groupBy !== "none" ? 1 : 0) +
    (showSuppressed ? 1 : 0);

  // Keep the keyboard cursor in range as the result set changes.
  useEffect(() => {
    setCursor((c) => Math.max(0, Math.min(c, ordered.length - 1)));
  }, [ordered.length]);

  // Keyboard navigation (j/k move, Enter open, / search, x select, Esc clear).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "/" && !isEditableTarget(e.target)) {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (isEditableTarget(e.target)) return;
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(c + 1, ordered.length - 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      } else if (e.key === "Enter") {
        const f = ordered[cursor];
        if (f) navigate(`/findings/${f.id}`);
      } else if (e.key === "x") {
        const f = ordered[cursor];
        if (f) toggleSelect(f.id);
      } else if (e.key === "Escape") {
        setSelected(new Set());
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ordered, cursor, navigate]);

  useEffect(() => {
    rowRefs.current[cursor]?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // Toggle only the currently-visible rows, preserving any selection that lives
  // outside the active filter. `selected` can retain ids that are no longer in
  // `ordered` after a filter change, so the header state must be derived from
  // the visible rows — never from `selected.size` alone.
  function toggleSelectAll() {
    setSelected((prev) => {
      const next = new Set(prev);
      const allVisibleSelected =
        ordered.length > 0 && ordered.every((f) => prev.has(f.id));
      if (allVisibleSelected) {
        for (const f of ordered) next.delete(f.id);
      } else {
        for (const f of ordered) next.add(f.id);
      }
      return next;
    });
  }

  function exportSelected() {
    const chosen = ordered.filter((f) => selected.has(f.id));
    if (chosen.length === 0) return;
    void navigator.clipboard.writeText(buildFindingsTableMarkdown(chosen));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function bulkSetStatus(status: TriageStatus) {
    for (const id of selected) setTriage.mutate({ fingerprint: id, status });
  }

  function setSortKey(key: SortKey) {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key, dir: DEFAULT_DIR[key] },
    );
  }

  const allSelected =
    ordered.length > 0 && ordered.every((f) => selected.has(f.id));
  const someSelected = !allSelected && ordered.some((f) => selected.has(f.id));

  // Renders a single finding row; `globalIndex` indexes into `ordered` so the
  // keyboard cursor and ref array line up across groups.
  let runningIndex = -1;
  function renderRow(f: Finding) {
    runningIndex += 1;
    const idx = runningIndex;
    return (
      <FindingRow
        key={f.id}
        index={idx}
        finding={f}
        selected={selected.has(f.id)}
        highlighted={idx === cursor}
        crossProtocol={isCrossProtocol(f)}
        onToggleSelect={() => toggleSelect(f.id)}
        onClick={() => {
          setCursor(idx);
          navigate(`/findings/${f.id}`);
        }}
        rowRef={(el) => {
          rowRefs.current[idx] = el;
        }}
      />
    );
  }

  // ---------- Main register (loading / empty / table) ----------
  const emptyLabel =
    total > 0
      ? "No findings match the current filters"
      : canClaimCurrent
        ? "No findings detected in the current published snapshot"
        : scopeUnavailable
          ? "No published finding snapshot is available"
          : "Current finding status is unavailable";

  const registerContent = coldError ? (
    <WidgetCard title="Threat Register" icon={ShieldAlert}>
      <DataStateNotice tone="error" title="Findings unavailable">
        The findings request failed before any snapshot was loaded. No conclusion
        about the current security posture can be drawn.
      </DataStateNotice>
    </WidgetCard>
  ) : isLoading ? (
    <WidgetCard title="Threat Register" icon={ShieldAlert} flush>
      <div className="space-y-px p-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full rounded-[2px]" />
        ))}
      </div>
    </WidgetCard>
  ) : ordered.length === 0 ? (
    <WidgetCard title="Threat Register" icon={ShieldAlert}>
      <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <span className="flex h-12 w-12 items-center justify-center rounded-[4px] bg-primary/10 ring-1 ring-inset ring-primary/20">
          <ShieldAlert className="h-6 w-6 text-primary" />
        </span>
        <p className="font-mono text-xs uppercase tracking-[0.12em] text-muted-foreground">
          {emptyLabel}
        </p>
        {total === 0 && canClaimCurrent && (
          <button
            onClick={() => navigate("/scans")}
            className="font-mono text-xs uppercase tracking-[0.08em] text-primary transition-colors hover:text-primary/80"
          >
            ▸ Go to Scans
          </button>
        )}
      </div>
    </WidgetCard>
  ) : (
    <WidgetCard
      title="Threat Register"
      icon={ShieldAlert}
      flush
      action={
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          Showing {pad2(ordered.length)} <span className="text-muted-foreground/50">/</span> {pad2(total)}
        </span>
      }
    >
      <div>
        <table className="w-full table-fixed border-collapse text-left">
          <thead>
            <tr className="border-b border-border bg-black/20">
              <th className="w-12 px-2 py-2 text-center">
                <input
                  type="checkbox"
                  ref={(el) => {
                    if (el) el.indeterminate = someSelected;
                  }}
                  checked={allSelected}
                  onChange={toggleSelectAll}
                  className="check-tac"
                  aria-label="Select all"
                />
              </th>
              <SortHeader label="Severity" active={sort.key === "severity"} dir={sort.dir} onClick={() => setSortKey("severity")} className="w-[108px] text-center" />
              <Th className="text-center">Finding</Th>
              <Th className="w-[280px] text-center">Flow</Th>
              <SortHeader label="Category" active={sort.key === "category"} dir={sort.dir} onClick={() => setSortKey("category")} className="w-[172px] text-center" />
              <SortHeader label="Confidence" active={sort.key === "confidence"} dir={sort.dir} onClick={() => setSortKey("confidence")} className="w-[80px] text-center" />
            </tr>
          </thead>
          <tbody>
            {groups
              ? groups.map(([label, list]) => (
                  <GroupSection key={label} groupBy={groupBy} label={label} count={list.length}>
                    {list.map((f) => renderRow(f))}
                  </GroupSection>
                ))
              : ordered.map((f) => renderRow(f))}
          </tbody>
        </table>
      </div>
    </WidgetCard>
  );

  const mainContent = (
    <div className="space-y-2">
      {cachedRefreshError && (
        <DataStateNotice tone="warning" title="Showing cached findings">
          The latest refresh failed. Values below are cached
          {dataUpdatedAt > 0
            ? ` from ${new Date(dataUpdatedAt).toLocaleString()}`
            : ""}
          ; current status is unavailable.
        </DataStateNotice>
      )}
      {!cachedRefreshError && scopeUnavailable && (
        <DataStateNotice tone="error" title="Published snapshot unavailable">
          The server did not provide an available published findings snapshot.
          Empty results cannot be interpreted as an all-clear.
        </DataStateNotice>
      )}
      {!cachedRefreshError && !scopeUnavailable && scopeStale && (
        <DataStateNotice tone="warning" title="Published snapshot is stale">
          Showing snapshot {snapshot?.scanId ?? "with unknown scan ID"}. The live
          projection is not aligned with this revision, so these findings are not
          a current-state verdict.
        </DataStateNotice>
      )}
      {registerContent}
    </div>
  );

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1600px] space-y-3">
        {/* ---------- Command header ---------- */}
        <header className="min-w-0">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Security Findings <span className="text-primary/60">//</span> Threat Register
          </p>
          <h1 className="mt-1.5 flex items-center gap-2.5 font-mono text-2xl font-bold uppercase tracking-[0.04em] text-foreground sm:text-[26px]">
            <span className="flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/10 ring-1 ring-inset ring-primary/30">
              <ShieldAlert className="h-4 w-4 text-primary" />
            </span>
            <span className="text-primary">▸</span>
            Findings
            <span className="font-mono text-base font-semibold tabular-nums text-muted-foreground">
              {canShowSnapshotCounts ? pad2(total) : "--"}
            </span>
            <span className="blink-caret text-primary" aria-hidden>
              _
            </span>
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Detected attack paths and exposures across your agent, MCP, and A2A infrastructure.
          </p>
        </header>

        {/* ---------- Top bar: clickable severity strip + search ---------- */}
        <div className="flex flex-wrap items-center gap-2">
          {/* SOC register strip — each segment is the severity / cross-protocol filter */}
          <div className="card-elevated relative flex flex-wrap items-stretch divide-x divide-border/70 overflow-hidden rounded-md">
            <span aria-hidden className="absolute left-0 top-0 z-10 h-px w-14 bg-primary/80" />
            <SevStat
              label="Total"
              count={canShowSnapshotCounts ? pad2(total) : "--"}
              color={ACCENT}
              active={activeSeverities.size === 0 && !xproto}
              onClick={() => patch({ sev: null, xproto: null })}
              title="Show all severities"
            />
            {SEVERITY_LEVELS.map((lvl) => {
              const n = counts[lvl] ?? 0;
              return (
                <SevStat
                  key={lvl}
                  label={SEVERITY[lvl].label}
                  count={canShowSnapshotCounts ? pad2(n) : "--"}
                  color={severityColor(lvl)}
                  active={activeSeverities.has(lvl)}
                  dim={canShowSnapshotCounts && n === 0}
                  onClick={() => toggleCsv("sev", activeSeverities, lvl)}
                  title={`Filter to ${SEVERITY[lvl].label} severity`}
                />
              );
            })}
            <SevStat
              label="X-Proto"
              count={canShowSnapshotCounts ? pad2(counts.xproto) : "--"}
              color={XPROTO_ACCENT}
              icon={GitBranchPlus}
              active={xproto}
              dim={canShowSnapshotCounts && counts.xproto === 0}
              onClick={() => patch({ xproto: xproto ? null : "1" })}
              title="Show only cross-protocol findings (A2A ↔ MCP)"
            />
          </div>

          <div className="relative ml-auto">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              ref={searchRef}
              type="text"
              placeholder="search findings…  (/)"
              value={search}
              onChange={(e) => patch({ q: e.target.value })}
              className="h-9 w-72 rounded-[3px] border border-border bg-black/30 pl-8 pr-3 font-mono text-xs text-foreground placeholder:text-muted-foreground/70 focus-visible:border-primary/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/40"
            />
          </div>
        </div>

        {/* ---------- Facet rail + register ---------- */}
        <Sidebar
          className="items-start"
          sidePosition="left"
          sideWidth={railOpen ? "11.5rem" : "2.75rem"}
          contentMin="70%"
          gap="0.75rem"
          side={
            railOpen ? (
              <FacetRail
                activeTriage={activeTriage}
                triageCounts={triageCounts}
                onToggleTriage={(s) => toggleCsv("triage", activeTriage, s)}
                onClearTriage={() => patch({ triage: null })}
                minConf={minConf}
                onSetConf={(c) => patch({ conf: c === 0 ? null : String(c) })}
                groupBy={groupBy}
                onSetGroup={(g) => patch({ group: g === "none" ? null : g })}
                showSuppressed={showSuppressed}
                onToggleSuppressed={() => patch({ suppressed: showSuppressed ? null : "1" })}
                activeCount={activeFacetCount}
                onReset={() => patch({ triage: null, conf: null, group: null, suppressed: null })}
                onCollapse={() => setRailOpen(false)}
              />
            ) : (
              <CollapsedRail
                activeCount={activeFacetCount}
                onExpand={() => setRailOpen(true)}
              />
            )
          }
          main={mainContent}
        />
      </div>

      {/* ---------- Floating bulk action bar ---------- */}
      {selected.size > 0 && (
        <div className="pointer-events-none fixed inset-x-0 bottom-4 z-40 flex justify-center px-4">
          <div className="pointer-events-auto flex items-center gap-2 rounded-md border border-primary/40 bg-card/95 px-3 py-2 backdrop-blur-md elev-3">
            <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-primary">
              {pad2(selected.size)} selected
            </span>
            <span className="mx-1 h-4 w-px bg-border/70" />
            <BulkStatusMenu onPick={bulkSetStatus} />
            <button
              onClick={exportSelected}
              className="inline-flex items-center gap-1.5 rounded-[3px] border border-border bg-black/30 px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.06em] text-foreground/80 transition-colors hover:border-primary/50 hover:text-primary"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" /> Export
                </>
              )}
            </button>
            <button
              onClick={() => setSelected(new Set())}
              className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground transition-colors hover:text-foreground"
            >
              <X className="h-3 w-3" /> Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ----------------------------------------------------------------------
// Clickable severity / cross-protocol summary segment.
// ----------------------------------------------------------------------
function SevStat({
  label,
  count,
  color,
  active,
  dim,
  icon: Icon,
  onClick,
  title,
}: {
  label: string;
  count: string;
  color: string;
  active: boolean;
  dim?: boolean;
  icon?: typeof GitBranchPlus;
  onClick: () => void;
  title?: string;
}) {
  const muted = dim && !active;
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-pressed={active}
      className={cn(
        "relative flex items-center gap-2 px-3 py-2 outline-none transition-colors",
        "focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-primary/50",
        active ? "bg-white/[0.04]" : "hover:bg-white/[0.025]",
      )}
      style={active ? { boxShadow: `inset 0 -2px 0 0 ${color}` } : undefined}
    >
      {Icon ? (
        <Icon
          className="h-3 w-3 shrink-0"
          style={{ color: muted ? "rgb(var(--mauve-8-raw))" : color }}
        />
      ) : (
        <span
          className="h-2 w-2 shrink-0 rounded-[1px]"
          style={{
            backgroundColor: muted ? "rgb(var(--mauve-8-raw))" : color,
            boxShadow: active ? `0 0 6px -1px ${color}` : undefined,
          }}
        />
      )}
      <span
        className={cn(
          "font-mono text-[10px] uppercase tracking-[0.14em]",
          active ? "text-foreground/90" : "text-muted-foreground",
        )}
      >
        {label}
      </span>
      <span
        className="font-mono text-sm font-bold tabular-nums"
        style={{ color: muted ? "rgb(var(--mauve-9-raw))" : color }}
      >
        {count}
      </span>
    </button>
  );
}

// ----------------------------------------------------------------------
// Left facet rail — secondary filters as faceted-search groups.
// ----------------------------------------------------------------------
function FacetRail({
  activeTriage,
  triageCounts,
  onToggleTriage,
  onClearTriage,
  minConf,
  onSetConf,
  groupBy,
  onSetGroup,
  showSuppressed,
  onToggleSuppressed,
  activeCount,
  onReset,
  onCollapse,
}: {
  activeTriage: Set<string>;
  triageCounts: Record<TriageStatus, number>;
  onToggleTriage: (s: TriageStatus) => void;
  onClearTriage: () => void;
  minConf: number;
  onSetConf: (c: number) => void;
  groupBy: GroupBy;
  onSetGroup: (g: GroupBy) => void;
  showSuppressed: boolean;
  onToggleSuppressed: () => void;
  activeCount: number;
  onReset: () => void;
  onCollapse: () => void;
}) {
  return (
    <aside className="card-elevated relative overflow-hidden rounded-md">
      <span aria-hidden className="absolute left-0 top-0 z-10 h-px w-14 bg-primary/80" />
      <div className="flex items-center justify-between gap-2 border-b border-border/70 px-3 py-2.5">
        <div className="flex min-w-0 items-center gap-1.5">
          <SlidersHorizontal className="h-3.5 w-3.5 shrink-0 text-primary/80" />
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-foreground/90">
            Filters
          </span>
          {activeCount > 0 && (
            <span className="rounded-[2px] bg-primary/15 px-1 font-mono text-[9px] font-semibold tabular-nums text-primary">
              {activeCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {activeCount > 0 && (
            <button
              type="button"
              onClick={onReset}
              className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/70 transition-colors hover:text-primary"
            >
              reset
            </button>
          )}
          <button
            type="button"
            onClick={onCollapse}
            title="Collapse filters"
            className="flex h-6 w-6 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.05] hover:text-foreground"
          >
            <PanelLeftClose className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="divide-y divide-border/60">
        <FacetSection title="Status" onClear={activeTriage.size > 0 ? onClearTriage : undefined}>
          <div className="space-y-0.5">
            {TRIAGE_ORDER.map((s) => (
              <FacetCheck
                key={s}
                checked={activeTriage.has(s)}
                color={TRIAGE_META[s].color}
                label={TRIAGE_META[s].label}
                count={triageCounts[s]}
                onToggle={() => onToggleTriage(s)}
              />
            ))}
          </div>
        </FacetSection>

        <FacetSection title="Min confidence">
          <div className="grid grid-cols-4 gap-1">
            {CONF_OPTIONS.map((c) => (
              <FacetSeg
                key={c}
                active={minConf === c}
                label={c === 0 ? "ANY" : `${c}`}
                onClick={() => onSetConf(c)}
              />
            ))}
          </div>
        </FacetSection>

        <FacetSection title="Group by">
          <div className="grid grid-cols-2 gap-1">
            {GROUP_OPTIONS.map((o) => (
              <FacetSeg
                key={o.value}
                active={groupBy === o.value}
                label={o.label}
                onClick={() => onSetGroup(o.value)}
                className="justify-start text-left"
              />
            ))}
          </div>
        </FacetSection>

        <FacetSection title="Display">
          <FacetCheck
            checked={showSuppressed}
            color={ACCENT}
            label="Show suppressed"
            onToggle={onToggleSuppressed}
          />
        </FacetSection>
      </div>
    </aside>
  );
}

function CollapsedRail({
  activeCount,
  onExpand,
}: {
  activeCount: number;
  onExpand: () => void;
}) {
  return (
    <div className="card-elevated relative flex flex-col items-center gap-2 rounded-md px-1.5 py-2.5">
      <span aria-hidden className="absolute left-0 top-0 z-10 h-px w-8 bg-primary/80" />
      <button
        type="button"
        onClick={onExpand}
        title="Expand filters"
        className="flex h-7 w-7 items-center justify-center rounded-[3px] border border-border bg-black/30 text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary"
      >
        <PanelLeftOpen className="h-3.5 w-3.5" />
      </button>
      {activeCount > 0 && (
        <span className="rounded-[2px] bg-primary/15 px-1 py-0.5 font-mono text-[9px] font-semibold tabular-nums text-primary">
          {activeCount}
        </span>
      )}
      <span
        className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground/70"
        style={{ writingMode: "vertical-rl" }}
      >
        Filters
      </span>
    </div>
  );
}

function FacetSection({
  title,
  onClear,
  children,
}: {
  title: string;
  onClear?: () => void;
  children: ReactNode;
}) {
  return (
    <div className="px-3 py-2.5">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="font-mono text-[9px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          {title}
        </span>
        {onClear && (
          <button
            type="button"
            onClick={onClear}
            className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/70 transition-colors hover:text-primary"
          >
            clear
          </button>
        )}
      </div>
      {children}
    </div>
  );
}

function FacetCheck({
  checked,
  color,
  label,
  count,
  onToggle,
}: {
  checked: boolean;
  color: string;
  label: string;
  count?: number;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={checked}
      className={cn(
        "flex w-full items-center gap-2 rounded-[3px] px-1.5 py-1 text-left transition-colors",
        checked ? "bg-white/[0.04]" : "hover:bg-white/[0.025]",
      )}
    >
      <span
        className={cn(
          "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[2px] border transition-colors",
          checked ? "border-primary bg-primary" : "border-border bg-black/30",
        )}
      >
        {checked && <Check className="h-2.5 w-2.5 text-black" strokeWidth={3} />}
      </span>
      <span
        className="h-1.5 w-1.5 shrink-0 rounded-[1px]"
        style={{ backgroundColor: color }}
      />
      <span
        className={cn(
          "flex-1 truncate font-mono text-[11px] tracking-[0.02em]",
          checked ? "text-foreground" : "text-foreground/70",
        )}
      >
        {label}
      </span>
      {typeof count === "number" && (
        <span
          className={cn(
            "font-mono text-[10px] tabular-nums",
            checked ? "text-primary" : "text-muted-foreground/70",
          )}
        >
          {pad2(count)}
        </span>
      )}
    </button>
  );
}

function FacetSeg({
  active,
  label,
  onClick,
  className,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "truncate rounded-[3px] border px-2 py-1 text-center font-mono text-[10px] tracking-[0.04em] transition-colors",
        active
          ? "border-primary/60 bg-primary/15 text-primary"
          : "border-border bg-black/30 text-muted-foreground hover:border-mauve-7 hover:text-foreground",
        className,
      )}
    >
      {label}
    </button>
  );
}

function Th({ children, className }: { children: ReactNode; className?: string }) {
  const align = className?.includes("text-right")
    ? "justify-end"
    : className?.includes("text-center")
      ? "justify-center"
      : "justify-start";
  return (
    <th className={cn("px-3 py-2 align-middle", className)}>
      <span
        className={cn(
          "flex h-4 items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground",
          align,
        )}
      >
        {children}
      </span>
    </th>
  );
}

function SortHeader({
  label,
  active,
  dir,
  onClick,
  className,
}: {
  label: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
  className?: string;
}) {
  const rightAlign = className?.includes("text-right");
  const centerAlign = className?.includes("text-center");
  const justify = rightAlign
    ? "justify-end"
    : centerAlign
      ? "justify-center"
      : "justify-start";
  return (
    <th className={cn("px-3 py-2 align-middle", className)}>
      <button
        onClick={onClick}
        className={cn(
          "flex h-4 w-full items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors",
          active ? "text-primary" : "text-muted-foreground hover:text-foreground",
          justify,
          rightAlign && "flex-row-reverse",
        )}
      >
        {label}
        {active ? (
          dir === "asc" ? (
            <ArrowUp className="h-3 w-3" />
          ) : (
            <ArrowDown className="h-3 w-3" />
          )
        ) : (
          <ChevronsUpDown className="h-3 w-3 opacity-40" />
        )}
      </button>
    </th>
  );
}

function GroupSection({
  groupBy,
  label,
  count,
  children,
}: {
  groupBy: GroupBy;
  label: string;
  count: number;
  children: ReactNode;
}) {
  const display =
    groupBy === "triage"
      ? TRIAGE_META[label as TriageStatus]?.label ?? label
      : groupBy === "edge_kind"
        ? edgeLabel(label)
        : label;
  const color =
    groupBy === "severity"
      ? severityColor(label)
      : groupBy === "triage"
        ? TRIAGE_META[label as TriageStatus]?.color ?? ACCENT
        : ACCENT;
  return (
    <>
      <tr className="border-b border-border/60 bg-black/30">
        <td colSpan={6} className="px-3 py-1.5" style={{ boxShadow: `inset 2px 0 0 0 ${color}` }}>
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-foreground/80">
            {display}
          </span>
          <span className="ml-2 font-mono text-[10px] tabular-nums text-muted-foreground">
            {count}
          </span>
        </td>
      </tr>
      {children}
    </>
  );
}

function BulkStatusMenu({ onPick }: { onPick: (s: TriageStatus) => void }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button className="inline-flex items-center gap-1.5 rounded-[3px] border border-border bg-black/30 px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.06em] text-foreground/80 transition-colors hover:border-primary/50 hover:text-primary">
          Set status
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="start"
          side="top"
          sideOffset={6}
          className="z-50 min-w-[170px] rounded-md border border-border bg-card/95 p-1 backdrop-blur-md elev-3"
        >
          {TRIAGE_ORDER.map((s) => {
            const m = TRIAGE_META[s];
            return (
              <DropdownMenu.Item
                key={s}
                onSelect={() => onPick(s)}
                className="flex cursor-pointer items-center gap-2 rounded-[3px] px-2 py-1.5 text-xs outline-none focus:bg-white/[0.05] data-[highlighted]:bg-white/[0.05]"
              >
                <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: m.color }} />
                <span className="text-foreground/90">{m.label}</span>
              </DropdownMenu.Item>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

// Combined index / checkbox cell. Default state shows the row number;
// hovering the row or selecting it swaps in the checkbox affordance, with the
// selected state showing a filled tick.
function RowSelector({
  index,
  selected,
  onToggle,
  title,
}: {
  index: number;
  selected: boolean;
  onToggle: () => void;
  title: string;
}) {
  return (
    <label
      className="relative flex h-6 w-8 cursor-pointer items-center justify-center"
      onClick={(e) => e.stopPropagation()}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        className="peer sr-only"
        aria-label={`Select ${title}`}
      />
      {/* Number — visible by default; hidden on row-hover or when selected */}
      <span
        aria-hidden
        className={cn(
          "absolute inset-0 flex items-center justify-center font-mono text-[10px] tabular-nums text-muted-foreground/60 transition-opacity",
          "group-hover:opacity-0",
          selected && "opacity-0",
        )}
      >
        {pad2(index + 1)}
      </span>
      {/* Box — fades in on row-hover or when selected */}
      <span
        aria-hidden
        className={cn(
          "pointer-events-none flex h-3.5 w-3.5 items-center justify-center rounded-[2px] border transition-opacity",
          selected
            ? "border-primary bg-primary opacity-100"
            : "border-border bg-black/30 opacity-0 group-hover:opacity-100 peer-focus-visible:opacity-100",
        )}
      >
        {selected && <Check className="h-2.5 w-2.5 text-black" strokeWidth={3} />}
      </span>
    </label>
  );
}

function ConfidencePips({ value }: { value: number }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <span className="block text-center font-mono text-[13px] tabular-nums leading-none text-foreground">
      {v}
      <span className="ml-0.5 text-[10px] text-muted-foreground/70">%</span>
    </span>
  );
}

function FindingRow({
  index,
  finding: f,
  selected,
  highlighted,
  crossProtocol,
  onToggleSelect,
  onClick,
  rowRef,
}: {
  index: number;
  finding: Finding;
  selected: boolean;
  highlighted: boolean;
  crossProtocol: boolean;
  onToggleSelect: () => void;
  onClick: () => void;
  rowRef: (el: HTMLTableRowElement | null) => void;
}) {
  const color = (SEVERITY_BY_KEY[f.severity] ?? SEVERITY.low).solid;
  const conf = Math.round(f.confidence * 100);

  return (
    <tr
      ref={rowRef}
      onClick={onClick}
      className={cn(
        "group cursor-pointer border-b border-border/60 transition-colors last:border-0",
        highlighted ? "bg-primary/[0.07]" : "hover:bg-white/[0.03]",
        selected && "bg-primary/[0.05]",
      )}
    >
      <td
        className="px-2 py-3 align-middle"
        onClick={(e) => e.stopPropagation()}
      >
        <RowSelector
          index={index}
          selected={selected}
          onToggle={onToggleSelect}
          title={f.title}
        />
      </td>
      <td className="px-2 py-3 align-middle">
        <span className="inline-flex items-center gap-1.5">
          <span
            className="h-2.5 w-2.5 rounded-[1px]"
            style={{ backgroundColor: color, boxShadow: `0 0 6px -1px ${color}` }}
          />
          <span
            className="font-mono text-[10px] font-bold uppercase tracking-[0.1em]"
            style={{ color }}
          >
            {f.severity}
          </span>
        </span>
      </td>
      <td className="px-2 py-3 align-middle">
        <p className="truncate text-[13px] font-medium text-foreground">{f.title}</p>
        <p className="truncate text-[12px] text-muted-foreground">{f.description}</p>
      </td>
      <td className="px-2 py-3 align-middle">
        <div className="flex items-center gap-1.5 font-mono text-[11px]">
          <MiniHexIcon kind={f.source_kind} />
          <span className="min-w-0 flex-1 truncate text-foreground/80">{f.source_name}</span>
          <ArrowRight className="h-3 w-3 shrink-0 text-primary/50" />
          <MiniHexIcon kind={f.target_kind} />
          <span className="min-w-0 flex-1 truncate text-foreground/80">{f.target_name}</span>
          {crossProtocol && (
            <span
              className="ml-1 rounded-[2px] bg-purple-500/15 px-1 py-0.5 font-mono text-[8px] font-bold uppercase tracking-[0.06em] text-purple-300"
              title="Cross-protocol (A2A ↔ MCP)"
            >
              X-PROTO
            </span>
          )}
        </div>
      </td>
      <td className="px-2 py-3 align-middle">
        <p className="truncate text-[12px] text-foreground/80">{f.category}</p>
        {f.owasp_map.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {(f.owasp_map ?? []).map((tag) => (
              <span
                key={tag}
                className="rounded-[2px] border border-border bg-black/40 px-1 py-0.5 font-mono text-[9px] uppercase tracking-[0.06em] text-muted-foreground"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </td>
      <td className="px-2 py-3 align-middle">
        <ConfidencePips value={conf} />
      </td>
    </tr>
  );
}
