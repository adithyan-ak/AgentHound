import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Upload,
  FileJson,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@shared/ui/primitives/dialog";
import { cn } from "@shared/lib/utils";
import {
  IngestRequestError,
  useUploadScan,
  type IngestResult,
} from "@entities/scan";
import { FEEDBACK, SEVERITY, SIGNAL_OK } from "@shared/theme/tokens";

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

function incompleteRequiredStages(result: IngestResult) {
  return (result.stages ?? []).filter(
    (stage) => stage.required && stage.state !== "complete",
  );
}

function completedStage(result: IngestResult, name: string): boolean {
  return result.stages?.some(
    (stage) => stage.name === name && stage.state === "complete",
  ) ?? false;
}

const ghostBtn =
  "inline-flex h-8 items-center rounded-[3px] border border-border bg-black/30 px-3 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 transition-colors hover:border-mauve-7 hover:text-foreground";
const primaryBtn =
  "inline-flex h-8 items-center rounded-[3px] bg-primary px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-primary-foreground transition-colors hover:bg-primary/90";

export function ScanImport({ open, onClose, onSuccess }: ScanImportProps) {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [dragActive, setDragActive] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const attemptRef = useRef(0);
  const openRef = useRef(open);
  const { mutateAsync: uploadScan } = useUploadScan();
  const navigate = useNavigate();

  const reset = useCallback(() => {
    setStatus({ kind: "idle" });
    setDragActive(false);
  }, []);

  const handleClose = useCallback(() => {
    attemptRef.current += 1;
    openRef.current = false;
    reset();
    onClose();
  }, [onClose, reset]);

  useEffect(() => {
    openRef.current = open;
    if (!open) {
      attemptRef.current += 1;
      reset();
    }
  }, [open, reset]);

  const goTo = useCallback(
    (path: string) => {
      handleClose();
      navigate(path);
    },
    [handleClose, navigate],
  );

  const processFile = useCallback(
    async (file: File) => {
      const attempt = ++attemptRef.current;
      const isCurrent = () =>
        openRef.current && attemptRef.current === attempt;
      const validationError = validateScanFile(file);
      if (validationError) {
        if (isCurrent()) {
          setStatus({ kind: "error", message: validationError });
        }
        return;
      }

      if (!isCurrent()) return;
      setStatus({ kind: "uploading", fileName: file.name });

      let text: string;
      try {
        text = await readFileAsText(file);
      } catch (err) {
        if (isCurrent()) {
          setStatus({
            kind: "error",
            message: err instanceof Error ? err.message : "failed to read file",
          });
        }
        return;
      }
      if (!isCurrent()) return;

      try {
        JSON.parse(text);
      } catch (err) {
        if (isCurrent()) {
          setStatus({
            kind: "error",
            message:
              err instanceof Error
                ? `not valid JSON: ${err.message}`
                : "not valid JSON",
          });
        }
        return;
      }

      try {
        const result = await uploadScan(file);
        if (!isCurrent()) return;
        setStatus({ kind: "success", result, fileName: file.name });
        onSuccess?.();
      } catch (err) {
        if (isCurrent()) {
          if (err instanceof IngestRequestError && err.result) {
            setStatus({
              kind: "success",
              result: err.result,
              fileName: file.name,
            });
            onSuccess?.();
          } else {
            setStatus({
              kind: "error",
              message: err instanceof Error ? err.message : "upload failed",
            });
          }
        }
      }
    },
    [onSuccess, uploadScan],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLButtonElement>) => {
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

  const handleDragOver = useCallback((e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLButtonElement>) => {
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

  const result = status.kind === "success" ? status.result : null;
  const incompleteStages = result ? incompleteRequiredStages(result) : [];
  const warnings = result?.warnings ?? [];
  const failedOutcome = result?.outcome === "failed";
  const completeOutcome =
    result?.outcome === "complete" &&
    result.projection_status === "complete" &&
    incompleteStages.length === 0 &&
    warnings.length === 0;
  const canOpenGraph =
    result?.projection_status === "complete" &&
    completedStage(result, "write_nodes") &&
    completedStage(result, "write_edges");
  const canViewFindings =
    result?.published_revision != null &&
    completedStage(result, "analysis") &&
    completedStage(result, "snapshot") &&
    completedStage(result, "publication");

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
          <>
            <button
              type="button"
              data-testid="dropzone"
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragEnter={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => inputRef.current?.click()}
              className={cn(
                "flex w-full cursor-pointer flex-col items-center justify-center gap-2 rounded-[3px] border-2 border-dashed p-8 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary",
                dragActive
                  ? "border-primary/70 bg-primary/5"
                  : "border-border bg-black/20 hover:border-primary/40 hover:bg-white/[0.02]",
              )}
            >
              <FileJson className="h-8 w-8 text-muted-foreground" aria-hidden />
              <span className="font-mono text-xs uppercase tracking-[0.08em] text-foreground">
                Drop scan JSON here or choose a file
              </span>
              <span className="text-xs text-muted-foreground">
                Files produced by{" "}
                <code className="font-mono">agenthound scan</code>
              </span>
            </button>
            <input
              ref={inputRef}
              type="file"
              accept="application/json,.json"
              className="sr-only"
              tabIndex={-1}
              aria-label="Choose collector scan JSON"
              onChange={handleFileInput}
              data-testid="file-input"
            />
          </>
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
              role={completeOutcome ? "status" : "alert"}
              className={cn(
                "flex items-start gap-2 rounded-[3px] border p-3",
                completeOutcome
                  ? "border-emerald-500/30 bg-emerald-500/10"
                  : failedOutcome
                    ? "border-destructive/30 bg-destructive/10"
                    : "border-amber-400/30 bg-amber-400/10",
              )}
              style={{
                boxShadow: `inset 2px 0 0 0 ${
                  completeOutcome
                    ? SIGNAL_OK
                    : failedOutcome
                      ? SEVERITY.critical.solid
                      : FEEDBACK.warning.solid
                }`,
              }}
            >
              {completeOutcome ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-400" />
              ) : failedOutcome ? (
                <AlertCircle className="mt-0.5 h-4 w-4 text-destructive" />
              ) : (
                <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-300" />
              )}
              <div className="space-y-1">
                <p className="text-sm font-medium text-foreground">
                  {completeOutcome
                    ? `Imported ${status.fileName}`
                    : failedOutcome
                      ? `Import failed after writing ${status.fileName}`
                      : `Imported ${status.fileName} with incomplete results`}
                </p>
                <p className="text-xs text-muted-foreground">
                  {status.result.write_rows.nodes} node write rows,{" "}
                  {status.result.write_rows.edges} edge write rows. Scan ID:{" "}
                  <code className="font-mono text-foreground/80">
                    {status.result.scan_id}
                  </code>
                </p>
                {!completeOutcome && (
                  <p className="text-xs text-muted-foreground">
                    Outcome: {status.result.outcome ?? "unknown"} · projection:{" "}
                    {status.result.projection_status ?? "unknown"}
                  </p>
                )}
              </div>
            </div>
            {incompleteStages.length > 0 && (
              <div className="rounded-[3px] border border-border bg-black/25 px-3 py-2">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-amber-200">
                  Required stages not complete
                </p>
                <ul className="mt-1 space-y-1 text-xs text-muted-foreground">
                  {incompleteStages.map((stage) => (
                    <li key={stage.name}>
                      <span className="font-mono text-foreground/80">
                        {stage.name}
                      </span>{" "}
                      — {stage.state}
                      {stage.error ? `: ${stage.error}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {warnings.length > 0 && (
              <div className="rounded-[3px] border border-amber-400/25 bg-amber-400/5 px-3 py-2">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-amber-200">
                  Import warnings
                </p>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-xs text-muted-foreground">
                  {warnings.map((warning, index) => (
                    <li key={`${warning}-${index}`}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
            {!canOpenGraph && (
              <p className="text-xs text-muted-foreground">
                Explorer is withheld because the graph projection is not
                complete.
              </p>
            )}
            {!canViewFindings && (
              <p className="text-xs text-muted-foreground">
                Findings are withheld because analysis, snapshot, and
                publication did not all complete.
              </p>
            )}
            <div className="flex flex-wrap justify-end gap-2">
              <button className={ghostBtn} onClick={reset}>
                Import another
              </button>
              {canViewFindings && (
                <button className={ghostBtn} onClick={() => goTo("/findings")}>
                  View findings
                </button>
              )}
              {canOpenGraph && (
                <button className={primaryBtn} onClick={() => goTo("/explorer")}>
                  Open graph
                </button>
              )}
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
