import { useEffect } from "react";
import { useGraphStore } from "@/store/graph";

export function PathHighlight() {
  const clearHighlight = useGraphStore((s) => s.clearHighlight);

  useEffect(() => {
    return () => {
      clearHighlight();
    };
  }, [clearHighlight]);

  return null;
}
