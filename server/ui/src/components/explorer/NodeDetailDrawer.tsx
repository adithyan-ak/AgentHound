import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import { X } from "lucide-react";
import { fetchNode } from "@/api/graph";
import { useExplorerStore, type DrawerTab } from "@/store/explorer";
import { getHexConfig } from "@/lib/explorer/hex-config";
import { cn } from "@/lib/utils";
import { PropertiesTab } from "./drawer/PropertiesTab";
import { ConnectionsTab } from "./drawer/ConnectionsTab";
import { EvidenceTab } from "./drawer/EvidenceTab";
import { RemediationTab } from "./drawer/RemediationTab";

const TABS: Array<{ id: DrawerTab; label: string }> = [
  { id: "properties", label: "Properties" },
  { id: "connections", label: "Connections" },
  { id: "evidence", label: "Evidence" },
  { id: "remediation", label: "Remediation" },
];

export function NodeDetailDrawer() {
  const selectedNodeId = useExplorerStore((s) => s.selectedNodeId);
  const drawerOpen = useExplorerStore((s) => s.drawerOpen);
  const drawerTab = useExplorerStore((s) => s.drawerTab);
  const closeDrawer = useExplorerStore((s) => s.closeDrawer);
  const setDrawerTab = useExplorerStore((s) => s.setDrawerTab);

  const { data, isLoading } = useQuery({
    queryKey: ["explorer", "node", selectedNodeId],
    queryFn: () => fetchNode(selectedNodeId!),
    enabled: drawerOpen && selectedNodeId !== null,
    staleTime: 30_000,
  });

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && drawerOpen) {
        const target = e.target as HTMLElement;
        if (target?.tagName === "INPUT" || target?.tagName === "TEXTAREA") return;
        closeDrawer();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen, closeDrawer]);

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
        "glass border-t shadow-[0_-8px_40px_-8px_rgba(0,0,0,0.8)]",
        "animate-in slide-in-from-bottom-4 fade-in duration-200",
      )}
      style={{ height: "40vh", minHeight: 320 }}
      role="dialog"
      aria-label={`Details for ${name}`}
    >
      <div className="flex h-full flex-col">
        <div className="flex items-center border-b border-border bg-muted/60 px-4 py-3">
          <div className="flex items-center gap-3">
            <div
              className="flex h-9 w-9 items-center justify-center rounded-md border"
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
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
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
            <TabsPrimitive.List className="flex gap-1 rounded-full bg-muted p-1">
              {TABS.map((t) => (
                <TabsPrimitive.Trigger
                  key={t.id}
                  value={t.id}
                  className={cn(
                    "rounded-full px-3 py-1 text-xs font-medium transition-colors",
                    "data-[state=active]:bg-primary data-[state=active]:text-white",
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
            className="ml-auto flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label="Close details drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-auto px-6 py-5">
          {isLoading ? (
            <div className="flex items-center justify-center py-10 text-sm text-muted-foreground">
              Loading node details…
            </div>
          ) : !node ? (
            <div className="flex items-center justify-center py-10 text-sm text-muted-foreground">
              Node not found.
            </div>
          ) : (
            <>
              {drawerTab === "properties" && <PropertiesTab node={node} />}
              {drawerTab === "connections" && (
                <ConnectionsTab nodeId={selectedNodeId} edges={edges} />
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
