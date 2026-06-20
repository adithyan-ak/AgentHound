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
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { useFindings, useSetTriage, SEVERITY_RANK } from "@entities/finding";
import type { Finding } from "@entities/finding/model";
import { edgeLabel } from "@entities/edge";
import {
  TRIAGE_ORDER,
  TRIAGE_META,
  type TriageStatus,
} from "@shared/model/triage";
import { buildFindingsTableMarkdown } from "../lib/copy-report";
import { isEditableTarget } from "@shared/lib";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { MiniHexIcon } from "./MiniHexIcon";
import { TriageControl } from "./TriageControl";
import { MeterBar, WidgetCard } from "@shared/ui/widgets";
import { cn } from "@shared/lib/utils";
import {
  ACCENT,
  SEVERITY,
  SEVERITY_BY_KEY,
  severityColor,
  CHART_THEME,
} from "@shared/theme/tokens";

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

type GroupBy =
  | "none"
  | "severity"
  | "target"
  | "source"
  | "category"
  | "owasp"
  | "edge_kind"
  | "triage";

type SortKey = "severity" | "confidence" | "category" | "triage" | "title";
type SortDir = "asc" | "desc";

const GROUP_OPTIONS: Array<{ value: GroupBy; label: string }> = [
  { value: "none", label: "No grouping" },
  { value: "severity", label: "Group: Severity" },
  { value: "target", label: "Group: Target" },
  { value: "source", label: "Group: Source" },
  { value: "category", label: "Group: Category" },
  { value: "owasp", label: "Group: OWASP" },
  { value: "edge_kind", label: "Group: Relationship" },
  { value: "triage", label: "Group: Triage" },
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
  triage: "asc",
  title: "asc",
};

export function FindingsListPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const showSuppressed = params.get("suppressed") === "1";
  const { data: findings, isLoading } = useFindings(showSuppressed);
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
  const groupBy = (params.get("group") as GroupBy) ?? "none";
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

  function patch(updates: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(updates)) {
      if (v == null || v === "") next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  }

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
        case "triage":
          r =
            TRIAGE_ORDER.indexOf(statusOf(a.id)) -
            TRIAGE_ORDER.indexOf(statusOf(b.id));
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
                  ? f.owasp_map?.[0] ?? "—"
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

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[1600px] space-y-3">
        {/* ---------- Command header ---------- */}
        <header className="space-y-3">
          <div className="min-w-0">
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
                {pad2(total)}
              </span>
              <span className="blink-caret text-primary" aria-hidden>
                _
              </span>
            </h1>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Detected attack paths and exposures across your agent, MCP, and A2A infrastructure.
            </p>
          </div>

          {/* SOC register summary strip */}
          <div className="card-elevated relative flex flex-wrap items-center overflow-hidden rounded-md">
            <span aria-hidden className="absolute left-0 top-0 h-px w-14 bg-primary/80" />
            <div className="flex flex-wrap items-center divide-x divide-border/70">
              <RegisterSeg label="Total" value={pad2(total)} color={CHART_THEME.tooltip.text} />
              {SEVERITY_LEVELS.map((lvl) => {
                const n = counts[lvl] ?? 0;
                return (
                  <RegisterSeg
                    key={lvl}
                    label={SEVERITY[lvl].label}
                    value={pad2(n)}
                    color={severityColor(lvl)}
                    dim={n === 0}
                  />
                );
              })}
              <RegisterSeg
                label="X-Proto"
                value={pad2(counts.xproto)}
                color={CHART_THEME.tooltip.text}
                dim={counts.xproto === 0}
              />
            </div>
            <div className="ml-auto flex items-center gap-2 self-stretch border-l border-border/70 px-3.5 py-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
                Showing
              </span>
              <span className="font-mono text-[11px] font-semibold tabular-nums text-primary">
                {pad2(ordered.length)}
              </span>
              <span className="font-mono text-[10px] tabular-nums text-muted-foreground">
                / {pad2(total)}
              </span>
            </div>
          </div>
        </header>

        {/* ---------- Toolbar row 1: severity + cross-protocol + search ---------- */}
        <div className="flex flex-wrap items-center gap-2">
          <FilterChip
            active={activeSeverities.size === 0}
            onClick={() => patch({ sev: null })}
            color={ACCENT}
            label="All"
          />
          {SEVERITY_LEVELS.map((lvl) => (
            <FilterChip
              key={lvl}
              active={activeSeverities.has(lvl)}
              onClick={() => toggleCsv("sev", activeSeverities, lvl)}
              color={severityColor(lvl)}
              label={SEVERITY[lvl].label}
            />
          ))}
          <span className="mx-1 h-5 w-px bg-border/70" />
          <button
            onClick={() => patch({ xproto: xproto ? null : "1" })}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-[3px] border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.08em] transition-colors",
              xproto
                ? "border-purple-500/60 bg-purple-500/15 text-purple-300"
                : "border-border bg-black/30 text-muted-foreground hover:border-mauve-7 hover:text-foreground",
            )}
            title="Show only cross-protocol findings (A2A ↔ MCP)"
          >
            <GitBranchPlus className="h-3 w-3" />
            Cross-protocol
          </button>

          <div className="relative ml-auto">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              ref={searchRef}
              type="text"
              placeholder="search findings…  (/)"
              value={search}
              onChange={(e) => patch({ q: e.target.value })}
              className="h-8 w-72 rounded-[3px] border border-border bg-black/30 pl-8 pr-3 font-mono text-xs text-foreground placeholder:text-muted-foreground/70 focus-visible:border-primary/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/40"
            />
          </div>
        </div>

        {/* ---------- Toolbar row 2: triage + group + confidence ---------- */}
        <div className="flex flex-wrap items-center gap-2">
          <FilterChip
            active={activeTriage.size === 0}
            onClick={() => patch({ triage: null })}
            color={ACCENT}
            label="Any status"
          />
          {TRIAGE_ORDER.map((s) => (
            <FilterChip
              key={s}
              active={activeTriage.has(s)}
              onClick={() => toggleCsv("triage", activeTriage, s)}
              color={TRIAGE_META[s].color}
              label={TRIAGE_META[s].label}
            />
          ))}
          <span className="mx-1 h-5 w-px bg-border/70" />
          <select
            value={groupBy}
            onChange={(e) => patch({ group: e.target.value === "none" ? null : e.target.value })}
            className="h-8 rounded-[3px] border border-border bg-black/30 px-2 font-mono text-[11px] uppercase tracking-[0.06em] text-foreground/80 focus-visible:border-primary/50 focus-visible:outline-none"
          >
            {GROUP_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <select
            value={String(minConf)}
            onChange={(e) => patch({ conf: e.target.value === "0" ? null : e.target.value })}
            className="h-8 rounded-[3px] border border-border bg-black/30 px-2 font-mono text-[11px] uppercase tracking-[0.06em] text-foreground/80 focus-visible:border-primary/50 focus-visible:outline-none"
            title="Minimum confidence"
          >
            {CONF_OPTIONS.map((c) => (
              <option key={c} value={String(c)}>
                conf ≥ {c}%
              </option>
            ))}
          </select>
          <span className="mx-1 h-5 w-px bg-border/70" />
          <button
            onClick={() => patch({ suppressed: showSuppressed ? null : "1" })}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-[3px] border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.08em] transition-colors",
              showSuppressed
                ? "border-primary/60 bg-primary/15 text-primary"
                : "border-border bg-black/30 text-muted-foreground hover:border-mauve-7 hover:text-foreground",
            )}
            title="Include accepted-risk / false-positive findings"
          >
            Show suppressed
          </button>
        </div>

        {/* ---------- Selection / bulk action bar ---------- */}
        {selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-primary/30 bg-primary/[0.06] px-3 py-2">
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
                  <Copy className="h-3.5 w-3.5" /> Export selected
                </>
              )}
            </button>
            <button
              onClick={() => setSelected(new Set())}
              className="ml-auto inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground transition-colors hover:text-foreground"
            >
              <X className="h-3 w-3" /> Clear
            </button>
          </div>
        )}

        {/* ---------- Register table ---------- */}
        {isLoading ? (
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
                {total > 0 ? "No findings match the current filters" : "No findings detected"}
              </p>
              {total === 0 && (
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
                {pad2(ordered.length)} <span className="text-muted-foreground/50">/</span> {pad2(total)}
              </span>
            }
          >
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left">
                <thead>
                  <tr className="border-b border-border bg-black/20">
                    <th className="w-9 px-3 py-2">
                      <input
                        type="checkbox"
                        ref={(el) => {
                          if (el) el.indeterminate = someSelected;
                        }}
                        checked={allSelected}
                        onChange={toggleSelectAll}
                        className="h-3.5 w-3.5 cursor-pointer accent-primary"
                        aria-label="Select all"
                      />
                    </th>
                    <Th className="w-10 pr-2 text-right">#</Th>
                    <SortHeader label="Severity" active={sort.key === "severity"} dir={sort.dir} onClick={() => setSortKey("severity")} />
                    <SortHeader label="Triage" active={sort.key === "triage"} dir={sort.dir} onClick={() => setSortKey("triage")} />
                    <Th>Finding</Th>
                    <Th>Flow</Th>
                    <SortHeader label="Category" active={sort.key === "category"} dir={sort.dir} onClick={() => setSortKey("category")} />
                    <Th>OWASP</Th>
                    <SortHeader label="Confidence" active={sort.key === "confidence"} dir={sort.dir} onClick={() => setSortKey("confidence")} className="text-right" />
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
        )}
      </div>
    </div>
  );
}

function RegisterSeg({
  label,
  value,
  color,
  dim,
}: {
  label: string;
  value: string;
  color: string;
  dim?: boolean;
}) {
  return (
    <div className="flex items-center gap-2 px-3 py-2">
      <span
        className="h-2 w-2 shrink-0 rounded-[1px]"
        style={{
          backgroundColor: dim ? "rgb(var(--mauve-8-raw))" : color,
          boxShadow: dim ? undefined : `0 0 6px -1px ${color}`,
        }}
      />
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </span>
      <span
        className="font-mono text-sm font-bold tabular-nums"
        style={{ color: dim ? "rgb(var(--mauve-9-raw))" : color }}
      >
        {value}
      </span>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  color,
  label,
}: {
  active: boolean;
  onClick: () => void;
  color: string;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[3px] border px-2.5 py-1 font-mono text-[11px] font-medium uppercase tracking-[0.08em] transition-colors",
        active
          ? "border-transparent text-foreground"
          : "border-border bg-black/30 text-muted-foreground hover:border-mauve-7 hover:text-foreground",
      )}
      style={active ? { backgroundColor: `${color}1A`, boxShadow: `inset 0 0 0 1px ${color}66` } : undefined}
    >
      <span
        className="h-2 w-2 rounded-[1px]"
        style={{ backgroundColor: active ? color : "rgb(var(--mauve-8-raw))" }}
      />
      {label}
    </button>
  );
}

function Th({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <th
      className={cn(
        "px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground",
        className,
      )}
    >
      {children}
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
  return (
    <th className={cn("px-3 py-2", className)}>
      <button
        onClick={onClick}
        className={cn(
          "inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors",
          active ? "text-primary" : "text-muted-foreground hover:text-foreground",
          className?.includes("text-right") && "flex-row-reverse",
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
        <td colSpan={9} className="px-3 py-1.5" style={{ boxShadow: `inset 2px 0 0 0 ${color}` }}>
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
        "cursor-pointer border-b border-border/60 transition-colors last:border-0",
        highlighted ? "bg-primary/[0.07]" : "hover:bg-white/[0.03]",
        selected && "bg-primary/[0.05]",
      )}
    >
      <td className="px-3 py-3 align-middle" onClick={(e) => e.stopPropagation()}>
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelect}
          className="h-3.5 w-3.5 cursor-pointer accent-primary"
          aria-label={`Select ${f.title}`}
        />
      </td>
      <td
        className="px-3 py-3 text-right align-middle font-mono text-[10px] tabular-nums text-muted-foreground/60"
        style={{ boxShadow: `inset 2px 0 0 0 ${color}` }}
      >
        {pad2(index + 1)}
      </td>
      <td className="px-3 py-3 align-middle">
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
      <td className="px-3 py-3 align-middle">
        <TriageControl
          findingId={f.id}
          status={(f.triage?.status as TriageStatus) ?? "new"}
          compact
        />
      </td>
      <td className="max-w-sm px-3 py-3 align-middle">
        <p className="truncate text-[13px] font-medium text-foreground">{f.title}</p>
        <p className="truncate text-xs text-muted-foreground">{f.description}</p>
      </td>
      <td className="px-3 py-3 align-middle">
        <div className="flex items-center gap-1.5 font-mono text-[11px]">
          <MiniHexIcon kind={f.source_kind} />
          <span className="max-w-[100px] truncate text-foreground/80">{f.source_name}</span>
          <ArrowRight className="h-3 w-3 shrink-0 text-primary/50" />
          <MiniHexIcon kind={f.target_kind} />
          <span className="max-w-[100px] truncate text-foreground/80">{f.target_name}</span>
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
      <td className="px-3 py-3 align-middle">
        <span className="font-mono text-[11px] text-muted-foreground">{f.category}</span>
      </td>
      <td className="px-3 py-3 align-middle">
        <div className="flex flex-wrap gap-1">
          {(f.owasp_map ?? []).map((tag) => (
            <span
              key={tag}
              className="rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.06em] text-muted-foreground"
            >
              {tag}
            </span>
          ))}
        </div>
      </td>
      <td className="px-3 py-3 align-middle">
        <div className="flex items-center justify-end gap-2">
          <MeterBar value={conf} max={100} color={color} height={4} className="w-14" />
          <span className="w-9 text-right font-mono text-[11px] font-semibold tabular-nums text-foreground">
            {conf}%
          </span>
        </div>
      </td>
    </tr>
  );
}
