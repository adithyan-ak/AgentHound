import { useState, useCallback } from "react";
import { Search } from "lucide-react";
import {
  useShortestPath,
  useAllPaths,
  useWeightedPath,
} from "@/hooks/usePathfinding";
import type { PathResponse, NodeKind } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";

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
        <label className="block text-xs font-medium text-muted-foreground mb-1">
          Source Kind
        </label>
        <Select value={sourceKind} onValueChange={(v) => setSourceKind(v as NodeKind)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {NODE_KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {k}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div>
        <label className="block text-xs font-medium text-muted-foreground mb-1">
          Source Name
        </label>
        <Input
          type="text"
          value={sourceName}
          onChange={(e) => setSourceName(e.target.value)}
          placeholder="e.g. claude-desktop"
          required
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-muted-foreground mb-1">
          Target Kind
          <span className="ml-1 text-muted-foreground">(optional)</span>
        </label>
        <Select value={targetKind || "__any__"} onValueChange={(v) => setTargetKind(v === "__any__" ? "" : v as NodeKind)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__any__">Any</SelectItem>
            {NODE_KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {k}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div>
        <label className="block text-xs font-medium text-muted-foreground mb-1">
          Target Name
          <span className="ml-1 text-muted-foreground">(optional - leave empty for any)</span>
        </label>
        <Input
          type="text"
          value={targetName}
          onChange={(e) => setTargetName(e.target.value)}
          placeholder="e.g. prod-database"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-muted-foreground mb-2">
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
              <span className="text-sm text-muted-foreground capitalize">{alg}</span>
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-muted-foreground mb-1">
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

      <Button
        type="submit"
        disabled={isPending || !sourceName.trim()}
        className="w-full"
      >
        <Search className="h-4 w-4" />
        {isPending ? "Searching..." : "Find Paths"}
      </Button>
    </form>
  );
}
