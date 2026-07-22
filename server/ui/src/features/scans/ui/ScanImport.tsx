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
  | { kind: "reading"; fileName: string }
  | { kind: "preview"; file: File; summary: ArtifactSummary }
  | { kind: "uploading"; fileName: string }
  | { kind: "success"; result: IngestResult; fileName: string }
  | { kind: "error"; message: string };

interface ArtifactSummary {
  scanID: string;
  collector: string;
  timestamp: string;
  collectionPointID: string;
  networkContextID: string;
  quality: "strong" | "weak";
  networkQuality: "strong" | "unknown";
  networkClass: "unknown" | "offline" | "private" | "public" | "mixed";
  display: {
    hostname?: string;
    os?: string;
    architecture?: string;
  };
}

function objectValue(value: unknown, path: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

const unsafeDisplayCharacter = /\p{C}/u;

function optionalDisplayLabel(
  display: Record<string, unknown>,
  field: string,
): string | undefined {
  const value = display[field];
  if (value === undefined || value === "") return undefined;
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    Array.from(value).length > 255 ||
    unsafeDisplayCharacter.test(value)
  ) {
    throw new TypeError(`artifact.meta.identity.display.${field} is invalid`);
  }
  return value;
}

export function summarizeScanArtifact(value: unknown): ArtifactSummary {
  const root = objectValue(value, "artifact");
  const meta = objectValue(root.meta, "artifact.meta");
  if (meta.version !== 4 || meta.type !== "agenthound-ingest") {
    throw new TypeError("file must be an AgentHound ingest-v4 artifact");
  }
  const identity = objectValue(meta.identity, "artifact.meta.identity");
  const quality = stringValue(identity.quality, "artifact.meta.identity.quality");
  if (quality !== "strong" && quality !== "weak") {
    throw new TypeError("artifact.meta.identity.quality is invalid");
  }
  const networkQuality = stringValue(
    identity.network_quality,
    "artifact.meta.identity.network_quality",
  );
  if (networkQuality !== "strong" && networkQuality !== "unknown") {
    throw new TypeError("artifact.meta.identity.network_quality is invalid");
  }
  const networkClass = stringValue(
    identity.network_class,
    "artifact.meta.identity.network_class",
  );
  if (!["unknown", "offline", "private", "public", "mixed"].includes(networkClass)) {
    throw new TypeError("artifact.meta.identity.network_class is invalid");
  }
  const displayValue = identity.display === undefined
    ? {}
    : objectValue(identity.display, "artifact.meta.identity.display");
  const hostname = optionalDisplayLabel(displayValue, "hostname");
  const os = optionalDisplayLabel(displayValue, "os");
  const architecture = optionalDisplayLabel(displayValue, "architecture");
  return {
    scanID: stringValue(meta.scan_id, "artifact.meta.scan_id"),
    collector: stringValue(meta.collector, "artifact.meta.collector"),
    timestamp: stringValue(meta.timestamp, "artifact.meta.timestamp"),
    collectionPointID: stringValue(
      identity.collection_point_id,
      "artifact.meta.identity.collection_point_id",
    ),
    networkContextID: stringValue(
      identity.network_context_id,
      "artifact.meta.identity.network_context_id",
    ),
    quality,
    networkQuality,
    networkClass: networkClass as ArtifactSummary["networkClass"],
    display: {
      ...(hostname ? { hostname } : {}),
      ...(os ? { os } : {}),
      ...(architecture ? { architecture } : {}),
    },
  };
}

function pointAlias(collectionPointID: string): string {
  const digest = collectionPointID.replace(/^sha256:/, "");
  return `Point ${digest.slice(0, 8) || "unknown"}`;
}

function pointDisplay(
  collectionPointID: string,
  display?: { hostname?: string; os?: string; architecture?: string },
): string {
  return display?.hostname || pointAlias(collectionPointID);
}

function platformDisplay(display?: { os?: string; architecture?: string }): string {
  return [display?.os, display?.architecture].filter(Boolean).join(" / ");
}

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
    if (inputRef.current) inputRef.current.value = "";
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
      setStatus({ kind: "reading", fileName: file.name });

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

      let summary: ArtifactSummary;
      try {
        summary = summarizeScanArtifact(JSON.parse(text));
      } catch (err) {
        if (isCurrent()) {
          setStatus({
            kind: "error",
            message:
              err instanceof Error
                ? `cannot preview artifact: ${err.message}`
                : "cannot preview artifact",
          });
        }
        return;
      }
      if (!isCurrent()) return;
      setStatus({ kind: "preview", file, summary });
    },
    [],
  );

  const confirmImport = useCallback(async () => {
    if (status.kind !== "preview") return;
    const { file } = status;
    const attempt = ++attemptRef.current;
    const isCurrent = () => openRef.current && attemptRef.current === attempt;
    setStatus({ kind: "uploading", fileName: file.name });
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
  }, [onSuccess, status, uploadScan]);

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

        {status.kind === "reading" && (
          <div className="flex flex-col items-center justify-center gap-2 rounded-[3px] border border-border bg-black/20 p-8">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <p className="font-mono text-xs uppercase tracking-[0.08em] text-foreground">
              Reading {status.fileName}…
            </p>
          </div>
        )}

        {status.kind === "preview" && (
          <div className="flex flex-col gap-3" data-testid="artifact-preview">
            <div className="rounded-[3px] border border-primary/30 bg-primary/5 p-3">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-primary">
                Ready to import
              </p>
              <p className="mt-1 text-sm font-medium text-foreground">
                {pointDisplay(
                  status.summary.collectionPointID,
                  status.summary.display,
                )}
              </p>
              {platformDisplay(status.summary.display) && (
                <p className="text-xs text-muted-foreground">
                  {platformDisplay(status.summary.display)}
                </p>
              )}
              <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-muted-foreground">File</dt>
                <dd className="break-all text-foreground/85">{status.file.name}</dd>
                <dt className="text-muted-foreground">Collector</dt>
                <dd className="font-mono text-foreground/85">{status.summary.collector}</dd>
                <dt className="text-muted-foreground">Observed</dt>
                <dd className="font-mono text-foreground/85">{status.summary.timestamp}</dd>
                <dt className="text-muted-foreground">Point</dt>
                <dd className="text-foreground/85">{status.summary.quality}</dd>
                <dt className="text-muted-foreground">Network</dt>
                <dd className="text-foreground/85">
                  {status.summary.networkClass} · {status.summary.networkQuality}
                </dd>
              </dl>
              <details className="mt-3 text-xs text-muted-foreground">
                <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-[0.08em]">
                  Identity details
                </summary>
                <div className="mt-2 space-y-1 break-all font-mono text-[10px]">
                  <p>Scan: {status.summary.scanID}</p>
                  <p>Point: {status.summary.collectionPointID}</p>
                  <p>Network: {status.summary.networkContextID}</p>
                </div>
              </details>
            </div>
            <p className="text-xs text-muted-foreground">
              Nothing has been imported yet. Confirm that this artifact belongs
              to the current operation.
            </p>
            <div className="flex justify-end gap-2">
              <button type="button" className={ghostBtn} onClick={reset}>
                Choose another
              </button>
              <button type="button" className={primaryBtn} onClick={() => void confirmImport()}>
                Import
              </button>
            </div>
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
            <div className="rounded-[3px] border border-border bg-black/25 px-3 py-2 text-xs">
              <p className="font-medium text-foreground">
                {pointDisplay(
                  status.result.identity.collection_point_id,
                  status.result.identity.display,
                )}{" "}
                <span className="font-normal text-muted-foreground">
                  · {status.result.identity.recognition}
                </span>
              </p>
              {platformDisplay(status.result.identity.display) && (
                <p className="text-muted-foreground">
                  {platformDisplay(status.result.identity.display)}
                </p>
              )}
              <p className="mt-1 text-muted-foreground">
                Point {status.result.identity.quality} · network{" "}
                {status.result.identity.network_class} /{" "}
                {status.result.identity.network_quality}
              </p>
              <details className="mt-2 break-all font-mono text-[10px] text-muted-foreground">
                <summary className="cursor-pointer uppercase tracking-[0.08em]">
                  Identity details
                </summary>
                <p className="mt-1">Point: {status.result.identity.collection_point_id}</p>
                <p>Network: {status.result.identity.network_context_id}</p>
              </details>
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
