import { useCallback, useRef, useState } from "react";
import { Upload, FileJson, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { uploadScan, type IngestResult } from "@/api/scans";

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

export function ScanImport({ open, onClose, onSuccess }: ScanImportProps) {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [dragActive, setDragActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const reset = useCallback(() => {
    setStatus({ kind: "idle" });
    setDragActive(false);
  }, []);

  const handleClose = useCallback(() => {
    reset();
    onClose();
  }, [onClose, reset]);

  const processFile = useCallback(
    async (file: File) => {
      // Reject oversize / wrong-type files BEFORE reading them into
      // memory. A 4 GB binary loaded into a string would hang the tab.
      const validationError = validateScanFile(file);
      if (validationError) {
        setStatus({ kind: "error", message: validationError });
        return;
      }

      setStatus({ kind: "uploading", fileName: file.name });

      // Read the file as text using FileReader. We use FileReader (rather
      // than the newer file.text() Promise API) for broader environment
      // compatibility, including jsdom in tests.
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

      // Validate it parses as JSON in-memory before sending. A file that
      // doesn't parse won't ingest, so we surface that error locally rather
      // than waiting on a 400 round-trip.
      try {
        JSON.parse(text);
      } catch (err) {
        setStatus({
          kind: "error",
          message:
            err instanceof Error
              ? `not valid JSON: ${err.message}`
              : "not valid JSON",
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
    [onSuccess],
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
          <DialogTitle className="flex items-center gap-2">
            <Upload className="h-4 w-4 text-primary" />
            Import Scan
          </DialogTitle>
          <DialogDescription>
            Drop a collector JSON file (from <code>agenthound scan</code>) into
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
            className={`flex flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed p-8 cursor-pointer transition-colors ${
              dragActive
                ? "border-primary bg-primary/5"
                : "border-border hover:border-primary/50 hover:bg-accent/30"
            }`}
          >
            <FileJson className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-foreground">
              Drop scan JSON here or click to browse
            </p>
            <p className="text-xs text-muted-foreground">
              Files produced by <code>agenthound scan</code>
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
          <div className="flex flex-col items-center justify-center gap-2 rounded-md border p-8">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <p className="text-sm text-foreground">
              Uploading {status.fileName}...
            </p>
            <p className="text-xs text-muted-foreground">
              Validating, normalizing, and writing to the graph
            </p>
          </div>
        )}

        {status.kind === "success" && (
          <div className="flex flex-col gap-3">
            <div className="flex items-start gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3">
              <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-foreground">
                  Imported {status.fileName}
                </p>
                <p className="text-xs text-muted-foreground">
                  {status.result.nodes_written} nodes,{" "}
                  {status.result.edges_written} edges written. Scan ID:{" "}
                  <code>{status.result.scan_id}</code>
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={reset}>
                Import another
              </Button>
              <Button size="sm" onClick={handleClose}>
                Close
              </Button>
            </div>
          </div>
        )}

        {status.kind === "error" && (
          <div className="flex flex-col gap-3">
            <div
              role="alert"
              className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3"
            >
              <AlertCircle className="h-4 w-4 text-destructive mt-0.5" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-foreground">
                  Import failed
                </p>
                <p className="text-xs text-muted-foreground break-all">
                  {status.message}
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={reset}>
                Try again
              </Button>
              <Button size="sm" onClick={handleClose}>
                Close
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
