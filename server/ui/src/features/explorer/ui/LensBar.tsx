import { useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronDown, Check, RotateCcw } from "lucide-react";
import { LENS_LIST, type LensDefinition } from "@features/explorer/model/lens-config";
import {
  DEFAULT_SUB_PRESETS,
  useExplorerStore,
  type LensId,
} from "@features/explorer/model/store";
import { cn } from "@shared/lib/utils";

/**
 * A lens is "filtered" when its enabled sub-presets resolve to a different set
 * of visible edge kinds than the lens default. Empty means no relationships,
 * matching the unchecked controls literally.
 */
function lensIsFiltered(lens: LensDefinition, enabled: string[]): boolean {
  if (lens.subPresets.length === 0) return false;
  const current = enabled;
  const base = DEFAULT_SUB_PRESETS[lens.id] ?? [];
  return (
    current.length !== base.length || current.some((k) => !base.includes(k))
  );
}

interface LensPillProps {
  lens: LensDefinition;
  active: boolean;
  onClick: () => void;
}

function LensPill({ lens, active, onClick }: LensPillProps) {
  const Icon = lens.icon;
  const subPresets = useExplorerStore((s) => s.subPresets[lens.id] ?? []);
  const toggleSubPreset = useExplorerStore((s) => s.toggleSubPreset);
  const setSubPresets = useExplorerStore((s) => s.setSubPresets);
  const [open, setOpen] = useState(false);

  const hasSubPresets = lens.subPresets.length > 0;
  const isFiltered = lensIsFiltered(lens, subPresets);

  const pillClasses = cn(
    "group relative flex items-center gap-1.5 rounded-[3px] border px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.06em]",
    "transition-[background-color,color,border-color] duration-150 ease-out",
    "whitespace-nowrap select-none",
    active
      ? cn(lens.accentClass, "border-transparent")
      : "border-border bg-black/30 text-muted-foreground hover:border-mauve-7 hover:text-foreground",
  );

  const pillStyle = active
    ? { boxShadow: `0 0 20px -4px ${lens.activeTint}70` }
    : undefined;

  if (!hasSubPresets) {
    return (
      <button className={pillClasses} style={pillStyle} onClick={onClick}>
        <Icon className="h-3.5 w-3.5" strokeWidth={2.25} />
        <span>{lens.label}</span>
      </button>
    );
  }

  return (
    <DropdownMenu.Root open={open} onOpenChange={setOpen}>
      <div className={pillClasses} style={pillStyle}>
        {isFiltered && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setSubPresets(lens.id, DEFAULT_SUB_PRESETS[lens.id] ?? []);
            }}
            title={`Filtered: showing ${subPresets.length} of ${lens.subPresets.length} relationship types. Click to reset to default.`}
            aria-label={`${lens.label} relationships filtered — click to reset to default`}
            className={cn(
              "absolute -right-1 -top-1 z-10 h-2.5 w-2.5 rounded-full bg-amber-400 ring-2 ring-card",
              "transition-transform duration-150 hover:scale-125 focus-visible:scale-125 focus-visible:outline-none",
            )}
          />
        )}
        <button onClick={onClick} className="flex items-center gap-1.5">
          <Icon className="h-3.5 w-3.5" strokeWidth={2.25} />
          <span>{lens.label}</span>
        </button>
        <DropdownMenu.Trigger asChild>
          <button
            className={cn(
              "flex items-center justify-center rounded-full -mr-1 ml-0.5 h-4 w-4",
              "hover:bg-black/20 transition-colors",
            )}
            aria-label={`${lens.label} sub-presets`}
          >
            <ChevronDown className="h-3 w-3" strokeWidth={2.5} />
          </button>
        </DropdownMenu.Trigger>
      </div>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="start"
          sideOffset={8}
          className={cn(
            "min-w-[240px] rounded-md border border-border bg-card/95 p-1 backdrop-blur-md elev-3",
            "",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
            "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
            "data-[side=bottom]:slide-in-from-top-2 z-50",
          )}
        >
          <div className="px-2 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            {lens.label} · sub-presets
          </div>
          {lens.subPresets.map((sp) => {
            const enabled = subPresets.includes(sp.id);
            return (
              <DropdownMenu.Item
                key={sp.id}
                onSelect={(e) => {
                  e.preventDefault();
                  toggleSubPreset(lens.id, sp.id);
                }}
                className={cn(
                  "group/item flex cursor-pointer items-start gap-2 rounded-[3px] px-2 py-2 text-xs",
                  "outline-none focus:bg-white/[0.05] data-[highlighted]:bg-white/[0.05]",
                  "transition-colors",
                )}
              >
                <div
                  className={cn(
                    "mt-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-[2px] border",
                    enabled
                      ? "border-primary bg-primary"
                      : "border-border bg-transparent",
                  )}
                >
                  {enabled && (
                    <Check className="h-2.5 w-2.5 text-primary-foreground" strokeWidth={3} />
                  )}
                </div>
                <div className="flex flex-col">
                  <span className="font-medium text-foreground">{sp.label}</span>
                  <span className="text-[10px] text-muted-foreground leading-tight">
                    {sp.description}
                  </span>
                </div>
              </DropdownMenu.Item>
            );
          })}
          <DropdownMenu.Separator className="my-1 h-px bg-border/60" />
          <DropdownMenu.Item
            disabled={!isFiltered}
            onSelect={(e) => {
              e.preventDefault();
              setSubPresets(lens.id, DEFAULT_SUB_PRESETS[lens.id] ?? []);
            }}
            className={cn(
              "flex items-center gap-2 rounded-[3px] px-2 py-1.5 font-mono text-[11px] uppercase tracking-[0.06em] outline-none transition-colors",
              "cursor-pointer text-muted-foreground hover:text-foreground focus:bg-white/[0.05] data-[highlighted]:bg-white/[0.05]",
              "data-[disabled]:pointer-events-none data-[disabled]:cursor-default data-[disabled]:opacity-40",
            )}
          >
            <RotateCcw className="h-3 w-3" strokeWidth={2.25} />
            Reset to default
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

export function LensBar() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const setActiveLens = useExplorerStore((s) => s.setActiveLens);

  return (
    <div className="pointer-events-auto absolute left-1/2 top-4 z-30 -translate-x-1/2">
      <div
        className={cn(
          "relative flex items-center gap-1.5 overflow-hidden rounded-md border border-border bg-card/95 px-2 py-1.5 backdrop-blur-md",
          "elev-2",
        )}
      >
        <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
        <div className="px-1.5 font-mono text-[9px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          Lens
        </div>
        {LENS_LIST.map((lens) => (
          <LensPill
            key={lens.id}
            lens={lens}
            active={activeLens === lens.id}
            onClick={() => setActiveLens(lens.id as LensId)}
          />
        ))}
      </div>
    </div>
  );
}
