import { useEffect } from "react";
import { useRegisterEvents, useSigma } from "@react-sigma/core";
import { useGraphStore } from "@/store/graph";
import { useUIStore } from "@/store/ui";

export function useGraphEvents() {
  const sigma = useSigma();
  const registerEvents = useRegisterEvents();
  const selectNode = useGraphStore((s) => s.selectNode);
  const hoverNode = useGraphStore((s) => s.hoverNode);
  const clearHover = useGraphStore((s) => s.clearHover);
  const clearSelection = useGraphStore((s) => s.clearSelection);
  const openSidebar = useUIStore((s) => s.openSidebar);
  const closeSidebar = useUIStore((s) => s.closeSidebar);

  useEffect(() => {
    registerEvents({
      clickNode: ({ node }) => {
        selectNode(node);
        openSidebar();
      },
      enterNode: ({ node }) => {
        hoverNode(node);
        sigma.getContainer().style.cursor = "pointer";
      },
      leaveNode: () => {
        clearHover();
        sigma.getContainer().style.cursor = "default";
      },
      clickStage: () => {
        clearSelection();
        closeSidebar();
      },
    });
  }, [
    registerEvents,
    sigma,
    selectNode,
    hoverNode,
    clearHover,
    clearSelection,
    openSidebar,
    closeSidebar,
  ]);
}
