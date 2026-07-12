import * as TabsPrimitive from "@radix-ui/react-tabs";
import { X } from "lucide-react";
import { useNode } from "@entities/node";
import { useExplorerStore, type DrawerTab } from "@features/explorer/model/store";
import { getHexConfig } from "@shared/lib/hex-config";
import { cn } from "@shared/lib/utils";
import { useEscapeKey } from "@shared/lib/useEscapeKey";
import { PropertiesTab } from "./drawer/PropertiesTab";
import { ConnectionsTab } from "./drawer/ConnectionsTab";
import { EvidenceTab } from "./drawer/EvidenceTab";
import { RemediationTab } from "./drawer/RemediationTab";
import { FindingsTab } from "./drawer/FindingsTab";

const TABS: Array<{ id: DrawerTab; label: string }> = [
  { id: "properties", label: "Properties" },
  { id: "connections", label: "Connections" },
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence" },
  { id: "remediation", label: "Remediation" },
];

export function NodeDetailDrawer() {
  const selectedNodeId = useExplorerStore((s) => s.selectedNodeId);
  const drawerOpen = useExplorerStore((s) => s.drawerOpen);
  const drawerTab = useExplorerStore((s) => s.drawerTab);
  const closeDrawer = useExplorerStore((s) => s.closeDrawer);
  const setDrawerTab = useExplorerStore((s) => s.setDrawerTab);

  // Passing null while closed keeps node-detail requests scoped to an open
  // Explorer drawer.
  const { data, isLoading } = useNode(drawerOpen ? selectedNodeId : null);

  useEscapeKey(closeDrawer, { enabled: drawerOpen });

  if (!drawerOpen || !selectedNodeId) return null;

  const node = data?.node;
  const edges = data?.edges ?? [];
  const kind = node?.kinds[0] ?? "";
  const config = getHexConfig(kind);
  const Icon = config.icon;
  const name = String(
    node?.properties?.name ?? node?.properties?.uri ?? node?.properties?.path ?? selectedNodeId.slice(0, 12),
  );

  return (
    <div
      className={cn(
        "pointer-events-auto absolute bottom-0 left-0 right-0 z-30",
        "border-t border-border bg-card/95 shadow-[0_-8px_40px_-8px_rgba(0,0,0,0.8)] backdrop-blur-md",
        "animate-in slide-in-from-bottom-4 fade-in duration-200",
      )}
      style={{ height: "40vh", minHeight: 320 }}
      role="dialog"
      aria-label={`Details for ${name}`}
    >
      <div className="flex h-full flex-col">
        <div className="relative flex items-center border-b border-border bg-black/20 px-4 py-3">
          <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
          <div className="flex items-center gap-3">
            <div
              className="flex h-9 w-9 items-center justify-center rounded-[3px] border"
              style={{
                borderColor: config.strokeColor,
                background: `${config.strokeColor}15`,
              }}
            >
              <Icon
                className="h-4 w-4"
                style={{ color: config.strokeColor }}
                strokeWidth={2.25}
              />
            </div>
            <div className="flex flex-col">
              <div
                className="font-mono text-[10px] uppercase tracking-[0.14em]"
                style={{ color: config.strokeColor }}
              >
                {config.kindTag}
              </div>
              <div className="font-semibold text-foreground">{name}</div>
            </div>
          </div>

          <TabsPrimitive.Root
            value={drawerTab}
            onValueChange={(v) => setDrawerTab(v as DrawerTab)}
            className="ml-8"
          >
            <TabsPrimitive.List className="flex gap-0.5 rounded-[3px] border border-border bg-black/30 p-0.5">
              {TABS.map((t) => (
                <TabsPrimitive.Trigger
                  key={t.id}
                  value={t.id}
                  className={cn(
                    "rounded-[2px] px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.06em] transition-colors",
                    "data-[state=active]:bg-primary data-[state=active]:text-primary-foreground",
                    "data-[state=inactive]:text-muted-foreground data-[state=inactive]:hover:text-foreground",
                  )}
                >
                  {t.label}
                </TabsPrimitive.Trigger>
              ))}
            </TabsPrimitive.List>
          </TabsPrimitive.Root>

          <button
            onClick={closeDrawer}
            className="ml-auto flex h-7 w-7 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
            aria-label="Close details drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-auto px-6 py-5">
          {isLoading ? (
            <div className="flex items-center justify-center py-10 font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
              Loading node details…
            </div>
          ) : !node ? (
            <div className="flex items-center justify-center py-10 font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
              Node not found.
            </div>
          ) : (
            <>
              {drawerTab === "properties" && <PropertiesTab node={node} />}
              {drawerTab === "connections" && (
                <ConnectionsTab nodeId={selectedNodeId} edges={edges} />
              )}
              {drawerTab === "findings" && (
                <FindingsTab nodeId={selectedNodeId} />
              )}
              {drawerTab === "evidence" && <EvidenceTab node={node} />}
              {drawerTab === "remediation" && (
                <RemediationTab node={node} edges={edges} />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
