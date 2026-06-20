import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Upload, FileJson, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@shared/ui/primitives/dialog";
import { cn } from "@shared/lib/utils";
import { useUploadScan, type IngestResult } from "@entities/scan";
import { SIGNAL_OK } from "@shared/theme/tokens";

interface ScanImportProps {
  open: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

// Pre-upload validation. The dropzone's `accept` attribute is advisory
// and ignored on drag-drop, so a 4 GB binary or a .exe rename would
// otherwise be loaded into memory and hang the browser.
const MAX_SCAN_BYTES = 100 * 1024 * 1024; // 100 MB matches server cap

export function validateScanFile(file: File): string | null {
  if (file.size > MAX_SCAN_BYTES) {
    return "File too large; max 100 MB.";
  }
  if (!file.name.toLowerCase().endsWith(".json")) {
    return "File must be a .json file.";
  }
  // file.type may be empty on some browsers/OSes (especially drag-drop
  // from Finder/Explorer). Only reject if a wrong type is explicitly set.
  if (file.type && file.type !== "application/json") {
    return "File must be a .json file.";
  }
  return null;
}

type Status =
  | { kind: "idle" }
  | { kind: "uploading"; fileName: string }
  | { kind: "success"; result: IngestResult; fileName: string }
  | { kind: "error"; message: string };

const ghostBtn =
  "inline-flex h-8 items-center rounded-[3px] border border-border bg-black/30 px-3 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 transition-colors hover:border-mauve-7 hover:text-foreground";
const primaryBtn =
  "inline-flex h-8 items-center rounded-[3px] bg-primary px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-primary-foreground transition-colors hover:bg-primary/90";

export function ScanImport({ open, onClose, onSuccess }: ScanImportProps) {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [dragActive, setDragActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const { mutateAsync: uploadScan } = useUploadScan();
  const navigate = useNavigate();

  const reset = useCallback(() => {
    setStatus({ kind: "idle" });
    setDragActive(false);
  }, []);

  const handleClose = useCallback(() => {
    reset();
    onClose();
  }, [onClose, reset]);

  const goTo = useCallback(
    (path: string) => {
      handleClose();
      navigate(path);
    },
    [handleClose, navigate],
  );

  const processFile = useCallback(
    async (file: File) => {
      const validationError = validateScanFile(file);
      if (validationError) {
        setStatus({ kind: "error", message: validationError });
        return;
      }

      setStatus({ kind: "uploading", fileName: file.name });

      let text: string;
      try {
        text = await readFileAsText(file);
      } catch (err) {
        setStatus({
          kind: "error",
          message: err instanceof Error ? err.message : "failed to read file",
        });
        return;
      }

      try {
        JSON.parse(text);
      } catch (err) {
        setStatus({
          kind: "error",
          message:
            err instanceof Error ? `not valid JSON: ${err.message}` : "not valid JSON",
        });
        return;
      }

      try {
        const result = await uploadScan(file);
        setStatus({ kind: "success", result, fileName: file.name });
        onSuccess?.();
      } catch (err) {
        setStatus({
          kind: "error",
          message: err instanceof Error ? err.message : "upload failed",
        });
      }
    },
    [onSuccess, uploadScan],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);
      const file = e.dataTransfer.files?.[0];
      if (file) {
        void processFile(file);
      }
    },
    [processFile],
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  }, []);

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        void processFile(file);
      }
    },
    [processFile],
  );

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono uppercase tracking-[0.04em]">
            <Upload className="h-4 w-4 text-primary" />
            Import Scan
          </DialogTitle>
          <DialogDescription>
            Drop a collector JSON file (from <code className="font-mono text-foreground/80">agenthound scan</code>) into
            the area below to ingest it into the graph.
          </DialogDescription>
        </DialogHeader>

        {status.kind === "idle" && (
          <div
            data-testid="dropzone"
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragEnter={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => inputRef.current?.click()}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-[3px] border-2 border-dashed p-8 transition-colors",
              dragActive
                ? "border-primary/70 bg-primary/5"
                : "border-border bg-black/20 hover:border-primary/40 hover:bg-white/[0.02]",
            )}
          >
            <FileJson className="h-8 w-8 text-muted-foreground" />
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-foreground">
              Drop scan JSON here or click to browse
            </p>
            <p className="text-xs text-muted-foreground">
              Files produced by <code className="font-mono">agenthound scan</code>
            </p>
            <input
              ref={inputRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={handleFileInput}
              data-testid="file-input"
            />
          </div>
        )}

        {status.kind === "uploading" && (
          <div className="flex flex-col items-center justify-center gap-2 rounded-[3px] border border-border bg-black/20 p-8">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-foreground">
              Uploading {status.fileName}…
            </p>
            <p className="text-xs text-muted-foreground">
              Validating, normalizing, and writing to the graph
            </p>
          </div>
        )}

        {status.kind === "success" && (
          <div className="flex flex-col gap-3">
            <div
              className="flex items-start gap-2 rounded-[3px] border border-emerald-500/30 bg-emerald-500/10 p-3"
              style={{ boxShadow: `inset 2px 0 0 0 ${SIGNAL_OK}` }}
            >
              <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-400" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-foreground">
                  Imported {status.fileName}
                </p>
                <p className="text-xs text-muted-foreground">
                  {status.result.nodes_written} nodes, {status.result.edges_written} edges written.
                  Scan ID: <code className="font-mono text-foreground/80">{status.result.scan_id}</code>
                </p>
              </div>
            </div>
            <div className="flex flex-wrap justify-end gap-2">
              <button className={ghostBtn} onClick={reset}>
                Import another
              </button>
              <button className={ghostBtn} onClick={() => goTo("/findings")}>
                View findings
              </button>
              <button className={primaryBtn} onClick={() => goTo("/explorer")}>
                Open graph
              </button>
            </div>
          </div>
        )}

        {status.kind === "error" && (
          <div className="flex flex-col gap-3">
            <div
              role="alert"
              className="flex items-start gap-2 rounded-[3px] border border-destructive/30 bg-destructive/10 p-3"
              style={{ boxShadow: "inset 2px 0 0 0 rgb(var(--tomato-9-raw))" }}
            >
              <AlertCircle className="mt-0.5 h-4 w-4 text-destructive" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-foreground">Import failed</p>
                <p className="break-all text-xs text-muted-foreground">{status.message}</p>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button className={ghostBtn} onClick={reset}>
                Try again
              </button>
              <button className={primaryBtn} onClick={handleClose}>
                Close
              </button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
