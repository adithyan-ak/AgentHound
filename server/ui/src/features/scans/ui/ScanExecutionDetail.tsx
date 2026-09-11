import { useScan } from "@entities/scan";

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function records(value: unknown): Record<string, unknown>[] | null {
  if (!Array.isArray(value) || !value.every((item) => record(item) !== null)) return null;
  return value as Record<string, unknown>[];
}

function text(value: unknown): string {
  return typeof value === "string" && value !== "" ? value : "Not recorded";
}

// Error text can contain endpoint or credential material. Reveal it deliberately;
// recovery payloads remain in the detail API and are never rendered here.
function RecordedError({ value }: { value: unknown }) {
  return typeof value === "string" && value !== "" ? (
    <details>
      <summary className="cursor-pointer text-primary">Reveal recorded error</summary>
      <pre className="mt-1 whitespace-pre-wrap break-all text-xs">{value}</pre>
    </details>
  ) : null;
}

export function ScanExecutionDetail({ scanId }: { scanId: string }) {
  const query = useScan(scanId);
  if (query.isLoading) return <p role="status">Loading execution details…</p>;
  if (query.isError) return (
    <p role="alert">
      Execution details could not be refreshed.{' '}
      <button className="text-primary underline" onClick={() => void query.refetch()}>Retry</button>
    </p>
  );
  const scan = query.data;
  const identity = record(scan?.metadata?.collection_identity);
  const extra = record(scan?.metadata?.artifact_extra);
  const execution = record(extra?.scan_execution);
  const actions = records(execution?.actions);
  const recovery = records(execution?.recovery);
  const available = execution?.version === 1 && actions !== null && recovery !== null;
  const unresolved = recovery?.filter((item) => item.status !== "restored") ?? [];

  return (
    <div className="space-y-3 break-words text-sm">
      <p className="break-all font-mono text-xs">Scan: {scanId}</p>
      <p>Collection point: {text(identity?.collection_point_id)}<br />
        Network context: {text(identity?.network_context_id)}</p>
      <RecordedError value={scan?.error} />
      {!available ? <p>Full execution journal unavailable for this scan.</p> : (
        <>
          <p>{text(execution.status)} · Recorded update: {text(execution.updated_at)}</p>
          {unresolved.length > 0 && (
            <p role="alert" className="text-amber-200">
              {unresolved.length} unresolved cleanup records. Use the original scan artifact
              with collector recovery in its original collection environment. These are
              recorded outcomes; this view does not perform recovery.
            </p>
          )}
          <h3 className="font-semibold">Actions ({actions.length})</h3>
          {actions.length === 0 && <p>No actions recorded.</p>}
          {actions.map((item, index) => (
            <div key={index} className="space-y-1 rounded border border-border p-2">
              <p>{text(item.action)} · {text(item.status)}</p>
              <p className="break-all font-mono text-xs">Action ID: {text(item.id)}<br />
                Target: {text(item.target_id)}
                {item.resource_id ? <><br />Resource: {text(item.resource_id)}</> : null}
                {item.credential_id ? <><br />Credential ID: {text(item.credential_id)}</> : null}
                {item.recovery_id ? <><br />Recovery ID: {text(item.recovery_id)}</> : null}
              </p>
              <p>Outcome: {text(item.outcome)}</p>
              <RecordedError value={item.error} />
            </div>
          ))}
          <h3 className="font-semibold">Recovery ({recovery.length})</h3>
          {recovery.length === 0 && <p>No recovery records.</p>}
          {recovery.map((item, index) => (
            <div key={index} className="space-y-1 rounded border border-border p-2">
              <p>{text(item.action)} · {text(item.status)}</p>
              <p className="break-all font-mono text-xs">Recovery ID: {text(item.id)}<br />
                Action ID: {text(item.action_id)}</p>
              <RecordedError value={item.error} />
            </div>
          ))}
        </>
      )}
    </div>
  );
}
