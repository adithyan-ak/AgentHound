import { Terminal, Copy, Check } from "lucide-react";
import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

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
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            Trigger a Scan
          </DialogTitle>
          <DialogDescription>
            Scans are triggered from the CLI. Run one of these commands to
            collect data and ingest it into the graph.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          {COMMANDS.map((cmd, i) => (
            <Card key={i}>
              <CardContent className="p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-foreground">
                    {cmd.label}
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6"
                    onClick={() => handleCopy(cmd.command, i)}
                  >
                    {copiedIdx === i ? (
                      <Check className="h-3 w-3 text-emerald-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </Button>
                </div>
                <code className="block text-xs text-foreground font-mono bg-background/50 rounded px-2 py-1.5">
                  {cmd.command}
                </code>
                <p className="mt-1.5 text-[10px] text-muted-foreground">
                  {cmd.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
