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
    label: "Default Scan",
    command: "agenthound scan",
    description:
      "Collect local evidence, enumerate discovered services, and prove eligible access paths in one active run",
  },
  {
    label: "Add Network Targets",
    command: "agenthound scan <host|CIDR|@targets-file>",
    description:
      "Run the same autonomous scan and include the supplied host, network, or target file",
  },
  {
    label: "Deep Scan",
    command: "agenthound scan --deep",
    description: "Include bounded deeper collection while keeping the same workflow",
  },
  {
    label: "Stealth Scan",
    command: "agenthound scan --stealth",
    description:
      "Collect read-only evidence without active proofs, credential reuse, or mutations",
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
            Run the collector on the host you already control. It writes one
            self-contained JSON artifact; transfer that file and import it here
            for graph analysis. Server connectivity is not required during the
            scan.
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
