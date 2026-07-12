import { Terminal, Copy, Check } from "lucide-react";
import { useState, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@shared/ui/primitives/dialog";

interface NewScanProps {
  open: boolean;
  onClose: () => void;
}

const COMMANDS = [
  {
    label: "Full Scan",
    command: "agenthound scan",
    description: "Discover configs, enumerate MCP servers, ingest, and analyze",
  },
  {
    label: "Config Discovery",
    command: "agenthound scan --config",
    description: "Discover all MCP client configs on this machine",
  },
  {
    label: "MCP Enumeration",
    command: "agenthound scan --mcp",
    description: "Enumerate all discovered MCP servers",
  },
  {
    label: "A2A Agent Card",
    command: "agenthound scan --a2a --target <url>",
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

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono uppercase tracking-[0.04em]">
            <Terminal className="h-4 w-4 text-primary" />
            Trigger a Scan
          </DialogTitle>
          <DialogDescription>
            Scanning is a two-step flow: the CLI <strong>collects</strong> an artifact from your
            infrastructure, then the server <strong>ingests</strong> it into the graph. Run one of
            these commands to collect, then import the produced JSON here (Import Scan) — or point
            the CLI at a running server to ingest directly.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2.5">
          {COMMANDS.map((cmd, i) => (
            <div
              key={i}
              className="rounded-[3px] border border-border bg-black/30 p-3 transition-colors hover:border-mauve-7"
            >
              <div className="mb-1.5 flex items-center justify-between">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.1em] text-foreground">
                  {cmd.label}
                </span>
                <button
                  onClick={() => handleCopy(cmd.command, i)}
                  title="Copy command"
                  className="inline-flex h-6 w-6 items-center justify-center rounded-[2px] text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
                >
                  {copiedIdx === i ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>
              <code className="flex items-center gap-1.5 rounded-[2px] border border-border/70 bg-black/50 px-2 py-1.5 font-mono text-xs text-foreground">
                <span className="select-none text-primary/70">$</span>
                {cmd.command}
              </code>
              <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                {cmd.description}
              </p>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
