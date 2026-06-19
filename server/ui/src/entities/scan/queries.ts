import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import { deleteScan, fetchScans, uploadScan } from "./api";

// Page size for the scan-manager list. The dashboard requests its own smaller
// page (20) under a distinct cache key, so writes here never disturb it.
export const SCANS_LIST_LIMIT = 50;

export function useScans(limit = SCANS_LIST_LIMIT) {
  return useQuery({
    queryKey: qk.scans(limit),
    queryFn: () => fetchScans(limit, 0),
  });
}

// A scan import or delete mutates the underlying graph, so EVERY graph-derived
// cache — not just the scan list — must be refetched, otherwise the dashboard,
// explorer, findings, and query views can show pre-write data for up to the
// query staleTime. These prefix keys invalidate all parameterized variants
// (e.g. both the manager's ["scans",50] and the dashboard's ["scans",20]).
const GRAPH_DERIVED_KEY_PREFIXES: readonly (readonly string[])[] = [
  ["scans"],
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
  });
}
