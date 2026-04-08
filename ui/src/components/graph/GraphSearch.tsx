import { useState, useCallback } from "react";
import { useSigma } from "@react-sigma/core";
import { Search } from "lucide-react";
import { useNodeSearch } from "@/hooks/useNodeSearch";
import { useGraphStore } from "@/store/graph";
import { useUIStore } from "@/store/ui";
import { NODE_COLORS } from "@/lib/node-styles";

export function GraphSearch() {
  const sigma = useSigma();
  const graph = sigma.getGraph();
  const { search, focusNode } = useNodeSearch(graph);
  const selectNode = useGraphStore((s) => s.selectNode);
  const openSidebar = useUIStore((s) => s.openSidebar);

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<
    Array<{ id: string; name: string; kind: string }>
  >([]);
  const [open, setOpen] = useState(false);

  const handleSearch = useCallback(
    (value: string) => {
      setQuery(value);
      if (value.length >= 2) {
        setResults(search(value));
        setOpen(true);
      } else {
        setResults([]);
        setOpen(false);
      }
    },
    [search],
  );

  const handleSelect = useCallback(
    (nodeId: string) => {
      focusNode(nodeId);
      selectNode(nodeId);
      openSidebar();
      setQuery("");
      setResults([]);
      setOpen(false);
    },
    [focusNode, selectNode, openSidebar],
  );

  return (
    <div className="absolute top-4 left-4 z-10 w-72">
      <div className="relative">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search nodes..."
          value={query}
          onChange={(e) => handleSearch(e.target.value)}
          onFocus={() => results.length > 0 && setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 200)}
          className="w-full rounded-md border bg-card pl-9 pr-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>
      {open && results.length > 0 && (
        <div className="mt-1 max-h-60 overflow-y-auto rounded-md border bg-card shadow-md">
          {results.map((r) => (
            <button
              key={r.id}
              onClick={() => handleSelect(r.id)}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm hover:bg-accent text-left"
            >
              <span
                className="h-2.5 w-2.5 rounded-full flex-shrink-0"
                style={{
                  backgroundColor: NODE_COLORS[r.kind] ?? "#999",
                }}
              />
              <span className="truncate">{r.name}</span>
              <span className="ml-auto text-xs text-muted-foreground">
                {r.kind}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
