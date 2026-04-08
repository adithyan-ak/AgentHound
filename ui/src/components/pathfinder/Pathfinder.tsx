import { useState } from "react";
import { Route } from "lucide-react";
import { PathSelector } from "./PathSelector";
import { PathResults } from "./PathResults";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import type { PathResponse } from "@/api/types";

export function Pathfinder() {
  const [results, setResults] = useState<PathResponse | null>(null);

  return (
    <div className="flex h-full">
      <div className="w-[420px] flex-shrink-0 border-r border-border overflow-y-auto">
        <div className="p-4">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground mb-4">
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
        <Card className="max-w-md border-none bg-transparent shadow-none text-center">
          <CardHeader>
            <Route className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <CardTitle className="text-lg">
              Attack Path Analysis
            </CardTitle>
            <CardDescription className="leading-relaxed">
              Find paths between nodes in the trust graph. Select a source node kind and name,
              optionally specify a target, then choose an algorithm to discover how an attacker
              could traverse from one entity to another.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-left text-xs text-muted-foreground">
            <p>
              <span className="text-foreground font-medium">Shortest</span> -- BFS, finds the
              minimum-hop path between nodes.
            </p>
            <p>
              <span className="text-foreground font-medium">All</span> -- Enumerates all
              distinct paths up to max hops.
            </p>
            <p>
              <span className="text-foreground font-medium">Weighted</span> -- Dijkstra via
              APOC, uses edge risk weights to find the lowest-cost attack path.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
