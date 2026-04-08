import { X, Terminal, Copy, Check } from "lucide-react";
import { useState, useCallback } from "react";

interface NewScanProps {
  open: boolean;
  onClose: () => void;
}

const COMMANDS = [
  {
    label: "Config Discovery",
    command: "agenthound collect config --discover | agenthound ingest -",
    description: "Discover all MCP client configs on this machine",
  },
  {
    label: "MCP Enumeration",
    command: "agenthound collect mcp --discover | agenthound ingest -",
    description: "Enumerate all discovered MCP servers",
  },
  {
    label: "A2A Agent Card",
    command: "agenthound collect a2a --target <url> | agenthound ingest -",
    description: "Fetch and ingest an A2A agent card",
  },
];

export function NewScan({ open, onClose }: NewScanProps) {
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  const handleCopy = useCallback(async (text: string, idx: number) => {
    await navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  }, []);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/60" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl">
        <div className="flex items-center justify-between border-b border-zinc-700 px-4 py-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium text-zinc-100">
              Trigger a Scan
            </span>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-4">
          <p className="text-sm text-zinc-400 mb-4">
            Scans are triggered from the CLI. Run one of these commands to
            collect data and ingest it into the graph.
          </p>

          <div className="space-y-3">
            {COMMANDS.map((cmd, i) => (
              <div
                key={i}
                className="rounded-md border border-zinc-700 bg-zinc-800 p-3"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-zinc-300">
                    {cmd.label}
                  </span>
                  <button
                    onClick={() => handleCopy(cmd.command, i)}
                    className="flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200"
                  >
                    {copiedIdx === i ? (
                      <Check className="h-3 w-3 text-green-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </button>
                </div>
                <code className="block text-xs text-zinc-200 font-mono bg-zinc-900/50 rounded px-2 py-1.5">
                  {cmd.command}
                </code>
                <p className="mt-1.5 text-[10px] text-zinc-500">
                  {cmd.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
