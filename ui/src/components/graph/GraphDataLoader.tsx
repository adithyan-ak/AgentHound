import { useEffect, useRef } from "react";
import { useLoadGraph, useSigma } from "@react-sigma/core";
import { useGraphData } from "@/hooks/useGraph";
import { runLayout } from "@/lib/layout";

export function GraphDataLoader() {
  const sigma = useSigma();
  const loadGraph = useLoadGraph();
  const { data: graph, isLoading } = useGraphData();
  const layoutRanRef = useRef(false);

  useEffect(() => {
    if (!graph) return;

    loadGraph(graph);
    layoutRanRef.current = false;

    runLayout(graph).then(() => {
      layoutRanRef.current = true;
      sigma.refresh();
    });
  }, [graph, loadGraph, sigma]);

  if (isLoading) {
    return (
      <div className="absolute inset-0 flex items-center justify-center bg-background/80 z-10">
        <div className="text-sm text-muted-foreground">Loading graph...</div>
      </div>
    );
  }

  return null;
}
