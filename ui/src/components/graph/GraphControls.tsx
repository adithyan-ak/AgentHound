import { useCallback } from "react";
import { useSigma } from "@react-sigma/core";
import {
  ZoomIn,
  ZoomOut,
  Maximize,
  RotateCcw,
} from "lucide-react";
import { useGraphData } from "@/hooks/useGraph";
import { runLayout } from "@/lib/layout";

export function GraphControls() {
  const sigma = useSigma();
  const { data: graph } = useGraphData();

  const zoomIn = useCallback(() => {
    const camera = sigma.getCamera();
    camera.animatedZoom({ duration: 300 });
  }, [sigma]);

  const zoomOut = useCallback(() => {
    const camera = sigma.getCamera();
    camera.animatedUnzoom({ duration: 300 });
  }, [sigma]);

  const zoomToFit = useCallback(() => {
    const camera = sigma.getCamera();
    camera.animatedReset({ duration: 300 });
  }, [sigma]);

  const reLayout = useCallback(() => {
    if (!graph) return;
    runLayout(graph).then(() => sigma.refresh());
  }, [graph, sigma]);

  const buttons = [
    { icon: ZoomIn, action: zoomIn, title: "Zoom in" },
    { icon: ZoomOut, action: zoomOut, title: "Zoom out" },
    { icon: Maximize, action: zoomToFit, title: "Fit to screen" },
    { icon: RotateCcw, action: reLayout, title: "Re-layout" },
  ];

  return (
    <div className="absolute bottom-4 right-4 flex flex-col gap-1 z-10">
      {buttons.map(({ icon: Icon, action, title }) => (
        <button
          key={title}
          onClick={action}
          title={title}
          className="rounded-md bg-card border p-2 shadow-sm hover:bg-accent transition-colors"
        >
          <Icon className="h-4 w-4" />
        </button>
      ))}
    </div>
  );
}
