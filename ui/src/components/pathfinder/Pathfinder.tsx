import { useState } from "react";
import { Route } from "lucide-react";
import { PathSelector } from "./PathSelector";
import { PathResults } from "./PathResults";
import type { PathResponse } from "@/api/types";

export function Pathfinder() {
  const [results, setResults] = useState<PathResponse | null>(null);

  return (
    <div className="flex h-full">
      <div className="w-[420px] flex-shrink-0 border-r border-zinc-700 overflow-y-auto">
        <div className="p-4">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100 mb-4">
            <Route className="h-5 w-5 text-primary" />
            Pathfinder
          </h2>
          <PathSelector onResults={setResults} />
          {results && (
            <div className="mt-6">
              <PathResults paths={results.paths} />
            </div>
          )}
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center p-8">
        <div className="max-w-md text-center">
          <Route className="h-12 w-12 text-zinc-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-zinc-300 mb-2">
            Attack Path Analysis
          </h3>
          <p className="text-sm text-zinc-500 leading-relaxed">
            Find paths between nodes in the trust graph. Select a source node kind and name,
            optionally specify a target, then choose an algorithm to discover how an attacker
            could traverse from one entity to another.
          </p>
          <div className="mt-6 space-y-2 text-left text-xs text-zinc-500">
            <p>
              <span className="text-zinc-400 font-medium">Shortest</span> -- BFS, finds the
              minimum-hop path between nodes.
            </p>
            <p>
              <span className="text-zinc-400 font-medium">All</span> -- Enumerates all
              distinct paths up to max hops.
            </p>
            <p>
              <span className="text-zinc-400 font-medium">Weighted</span> -- Dijkstra via
              APOC, uses edge risk weights to find the lowest-cost attack path.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
