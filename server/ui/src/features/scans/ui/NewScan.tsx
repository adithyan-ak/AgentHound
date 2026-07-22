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

// `agenthound scan` only collects and writes a JSON artifact (default:
// ./scan-<id>.json); it does NOT update the server graph on its own. The graph
// and analysis are updated only by ingesting that artifact — either
// `agenthound-server ingest <file>` or Import on the Scans page (AH-UI-23).
const COMMANDS = [
  {
    label: "Default Local Workflow",
    command: `agenthound scan --output agenthound-scan.json && agenthound-server ingest agenthound-scan.json`,
    description:
      "Collect config and MCP evidence, then ingest only if collection succeeds; A2A requires the separate targeted command",
  },
  {
    label: "Default Local Scan",
    command: "agenthound scan",
    description:
      "Collection only: discover configs and enumerate MCP servers; then import the JSON artifact",
  },
  {
    label: "Config Discovery",
    command: "agenthound scan --config",
    description:
      "Discover all MCP client configs on this machine; writes a JSON artifact",
  },
  {
    label: "MCP Enumeration",
    command: "agenthound scan --mcp",
    description: "Enumerate all discovered MCP servers; writes a JSON artifact",
  },
  {
    label: "A2A Agent Card",
    command: "agenthound scan --a2a --target <url>",
    description: "Fetch an A2A agent card; writes a JSON artifact",
  },
  {
    label: "Ingest Artifact",
    command: "agenthound-server ingest scan-<id>.json",
    description:
      "Load a scan artifact into the graph and run analysis (or use Import on this page)",
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
            Collect and Ingest
          </DialogTitle>
          <DialogDescription>
            A collector scan alone writes JSON and does not update the server.
            Use the complete local workflow, or collect first and then ingest
            the artifact with the final command or Import on this page. The
            collector derives collection-point and network-context provenance
            automatically; there are no identity flags to configure.
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
              <code className="flex items-start gap-1.5 whitespace-pre-wrap break-all rounded-[2px] border border-border/70 bg-black/50 px-2 py-1.5 font-mono text-xs text-foreground">
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
