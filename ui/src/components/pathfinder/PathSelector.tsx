import { useState, useCallback } from "react";
import { Search } from "lucide-react";
import {
  useShortestPath,
  useAllPaths,
  useWeightedPath,
} from "@/hooks/usePathfinding";
import type { PathResponse, NodeKind } from "@/api/types";
import { cn } from "@/lib/utils";

const NODE_KINDS: NodeKind[] = [
  "MCPServer",
  "MCPTool",
  "MCPResource",
  "MCPPrompt",
  "A2AAgent",
  "A2ASkill",
  "AgentInstance",
  "Identity",
  "Credential",
  "Host",
  "ConfigFile",
  "InstructionFile",
  "ResourceGroup",
  "TrustZone",
];

type Algorithm = "shortest" | "all" | "weighted";

interface PathSelectorProps {
  onResults: (response: PathResponse) => void;
}

export function PathSelector({ onResults }: PathSelectorProps) {
  const [sourceKind, setSourceKind] = useState<NodeKind>("AgentInstance");
  const [sourceName, setSourceName] = useState("");
  const [targetKind, setTargetKind] = useState<NodeKind | "">("");
  const [targetName, setTargetName] = useState("");
  const [algorithm, setAlgorithm] = useState<Algorithm>("shortest");
  const [maxHops, setMaxHops] = useState(6);

  const shortest = useShortestPath();
  const all = useAllPaths();
  const weighted = useWeightedPath();

  const activeMutation =
    algorithm === "shortest"
      ? shortest
      : algorithm === "all"
        ? all
        : weighted;

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (!sourceName.trim()) return;

      const req = {
        source: sourceName.trim(),
        target: targetName.trim() || "*",
        source_kind: sourceKind,
        ...(targetKind && { target_kind: targetKind }),
        max_hops: maxHops,
        limit: 20,
      };

      activeMutation.mutate(req, { onSuccess: onResults });
    },
    [sourceName, targetName, sourceKind, targetKind, maxHops, activeMutation, onResults],
  );

  const isPending = shortest.isPending || all.isPending || weighted.isPending;
  const error = activeMutation.error;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-1">
          Source Kind
        </label>
        <select
          value={sourceKind}
          onChange={(e) => setSourceKind(e.target.value as NodeKind)}
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {NODE_KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-1">
          Source Name
        </label>
        <input
          type="text"
          value={sourceName}
          onChange={(e) => setSourceName(e.target.value)}
          placeholder="e.g. claude-desktop"
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-primary"
          required
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-1">
          Target Kind
          <span className="ml-1 text-zinc-500">(optional)</span>
        </label>
        <select
          value={targetKind}
          onChange={(e) => setTargetKind(e.target.value as NodeKind | "")}
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="">Any</option>
          {NODE_KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-1">
          Target Name
          <span className="ml-1 text-zinc-500">(optional - leave empty for any)</span>
        </label>
        <input
          type="text"
          value={targetName}
          onChange={(e) => setTargetName(e.target.value)}
          placeholder="e.g. prod-database"
          className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-2">
          Algorithm
        </label>
        <div className="flex gap-3">
          {(["shortest", "all", "weighted"] as const).map((alg) => (
            <label key={alg} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="algorithm"
                value={alg}
                checked={algorithm === alg}
                onChange={() => setAlgorithm(alg)}
                className="accent-primary"
              />
              <span className="text-sm text-zinc-300 capitalize">{alg}</span>
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-zinc-400 mb-1">
          Max Hops: {maxHops}
        </label>
        <input
          type="range"
          min={1}
          max={20}
          value={maxHops}
          onChange={(e) => setMaxHops(Number(e.target.value))}
          className="w-full"
        />
      </div>

      {error && (
        <div className="rounded-md bg-red-900/30 border border-red-800 px-3 py-2 text-sm text-red-300">
          {error instanceof Error ? error.message : "Request failed"}
        </div>
      )}

      <button
        type="submit"
        disabled={isPending || !sourceName.trim()}
        className={cn(
          "flex w-full items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
          isPending
            ? "bg-zinc-700 text-zinc-400 cursor-wait"
            : "bg-primary text-primary-foreground hover:bg-primary/90",
        )}
      >
        <Search className="h-4 w-4" />
        {isPending ? "Searching..." : "Find Paths"}
      </button>
    </form>
  );
}
