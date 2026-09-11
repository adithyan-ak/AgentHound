import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown } from "lucide-react";
import {
  TRIAGE_ORDER,
  TRIAGE_META,
  type TriageStatus,
} from "@shared/model/triage";
import { useSetTriage } from "@entities/finding";
import { cn } from "@shared/lib/utils";

interface TriageControlProps {
  findingId: string;
  /** Current triage status (controlled). List rows pass the inline
   * f.triage status; the dossier header passes the fetched status. */
  status: TriageStatus;
  /** Compact = inline register cell; full = dossier header. */
  compact?: boolean;
}

/**
 * Status dropdown shared by the findings register (inline, compact) and the
 * dossier header (full). Controlled: the current status is supplied by the
 * caller and writes go through the server-backed useSetTriage mutation. Stops
 * click propagation so it can live inside a clickable table row without
 * triggering row navigation.
 */
export function TriageControl({ findingId, status, compact = false }: TriageControlProps) {
  const setTriage = useSetTriage();
  const meta = TRIAGE_META[status] ?? TRIAGE_META.new;

  return (
    <span className="inline-flex flex-wrap items-center gap-1" onClick={(e) => e.stopPropagation()}>
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          onClick={(e) => e.stopPropagation()}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-[3px] border font-mono uppercase tracking-[0.06em] transition-colors",
            "border-border bg-black/30 text-foreground/80 hover:border-mauve-7 hover:text-foreground",
            compact ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-[11px]",
          )}
          disabled={setTriage.isPending}
          aria-busy={setTriage.isPending}
          aria-label="Set triage status"
        >
          <span
            className="h-1.5 w-1.5 flex-shrink-0 rounded-[1px]"
            style={{ backgroundColor: meta.color, boxShadow: `0 0 6px -1px ${meta.color}` }}
          />
          <span style={{ color: meta.color }}>{compact ? meta.short : meta.label}</span>
          {setTriage.isPending && <span className="text-muted-foreground">Saving…</span>}
          <ChevronDown className="h-3 w-3 opacity-60" strokeWidth={2.5} />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="start"
          sideOffset={6}
          onClick={(e) => e.stopPropagation()}
          className={cn(
            "z-50 min-w-[180px] rounded-md border border-border bg-card/95 p-1 backdrop-blur-md elev-3",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
          )}
        >
          <div className="px-2 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            Triage status
          </div>
          {TRIAGE_ORDER.map((s) => {
            const m = TRIAGE_META[s];
            const active = s === status;
            return (
              <DropdownMenu.Item
                key={s}
                onSelect={() => setTriage.mutate({ fingerprint: findingId, status: s })}
                className={cn(
                  "flex cursor-pointer items-center gap-2 rounded-[3px] px-2 py-1.5 text-xs outline-none",
                  "focus:bg-white/[0.05] data-[highlighted]:bg-white/[0.05]",
                )}
              >
                <span
                  className="h-2 w-2 flex-shrink-0 rounded-[1px]"
                  style={{ backgroundColor: m.color }}
                />
                <span className="flex-1 text-foreground/90">{m.label}</span>
                {active && <Check className="h-3.5 w-3.5 text-primary" strokeWidth={3} />}
              </DropdownMenu.Item>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
    {setTriage.isError && (
      <span role="alert" className="text-xs text-destructive">
        Status save failed.{' '}
        <button className="underline" onClick={() => {
          if (setTriage.variables) setTriage.mutate(setTriage.variables);
        }}>Retry</button>
      </span>
    )}
    </span>
  );
}
