import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import {
  deleteScan,
  fetchLatestCompletedScan,
  fetchLatestPublishedScan,
  fetchScan,
  fetchScanPage,
  fetchScans,
  IngestRequestError,
  uploadScan,
} from "./api";
import type { Scan, ScanStatus } from "./model";

// Page size for the scan-manager list. The dashboard requests its own smaller
// page (20) under a distinct cache key; scan writes invalidate the entire
// ["scans"] prefix below, so both the manager and dashboard pages refresh.
export const SCANS_LIST_LIMIT = 50;

const ACTIVE_SCAN_STATUSES = new Set<ScanStatus>(["pending", "running"]);

export function hasActiveScan(scans: Scan[] | undefined): boolean {
  return scans?.some((scan) => ACTIVE_SCAN_STATUSES.has(scan.status)) ?? false;
}

export function useScans(limit = SCANS_LIST_LIMIT) {
  return useQuery({
    queryKey: qk.scans(limit),
    queryFn: () => fetchScans(limit, 0),
    refetchInterval: (query) =>
      hasActiveScan(query.state.data) ? 2_000 : false,
  });
}

export function useScan(id: string | null) {
  return useQuery({
    queryKey: qk.scan(id ?? ""),
    queryFn: () => fetchScan(id ?? ""),
    enabled: id != null && id !== "",
  });
}

export function useScanPage(
  limit = SCANS_LIST_LIMIT,
  offset = 0,
  revision?: string,
) {
  return useQuery({
    queryKey: qk.scanPage(limit, offset, revision),
    queryFn: () => fetchScanPage(limit, offset, revision),
    refetchInterval: (query) =>
      hasActiveScan(query.state.data?.scans) ? 2_000 : false,
  });
}

export function useLatestCompletedScan(poll = false) {
  return useQuery({
    queryKey: qk.latestScan("completed"),
    queryFn: fetchLatestCompletedScan,
    refetchInterval: poll ? 2_000 : false,
  });
}

export function useLatestPublishedScan(poll = false) {
  return useQuery({
    queryKey: qk.latestScan("published"),
    queryFn: fetchLatestPublishedScan,
    refetchInterval: poll ? 2_000 : false,
  });
}

// A scan import or delete mutates the underlying graph, so EVERY graph-derived
// cache — not just the scan list — must be refetched, otherwise the dashboard,
// explorer, findings, and query views can show pre-write data for up to the
// query staleTime. These prefix keys invalidate all parameterized variants
// (e.g. both the manager's ["scans",50] and the dashboard's ["scans",20]).
const GRAPH_DERIVED_KEY_PREFIXES: readonly (readonly string[])[] = [
  ["scans"],
  ["scan"],
  ["graph"],
  ["nodes"],
  ["node"],
  ["edges"],
  ["findings"],
  ["finding-detail"],
  ["prebuilt-queries"],
  ["prebuilt"],
  ["explorer"],
  ["health"],
  ["posture"],
];

function invalidateGraphDerivedQueries(queryClient: QueryClient) {
  for (const queryKey of GRAPH_DERIVED_KEY_PREFIXES) {
    void queryClient.invalidateQueries({ queryKey });
  }
}

export function useDeleteScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteScan(id),
    onSuccess: () => invalidateGraphDerivedQueries(queryClient),
  });
}

export function useUploadScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => uploadScan(file),
    onSuccess: () => invalidateGraphDerivedQueries(queryClient),
    onError: (error) => {
      if (error instanceof IngestRequestError && error.result) {
        invalidateGraphDerivedQueries(queryClient);
      }
    },
  });
}
