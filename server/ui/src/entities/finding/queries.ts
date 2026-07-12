import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import {
  fetchFindingDetail,
  fetchFindings,
  getTriage,
  patchTriage,
  setTriage,
} from "./api";
import type { TriageStatus } from "@shared/model/triage";

// One findings cache for every surface that needs the full set (dashboard,
// findings list, node findings, references, navigation). includeSuppressed
// addresses a distinct cache entry so the register's "show suppressed"
// toggle does not disturb the default (hidden-suppressed) view.
export function useFindings(includeSuppressed = false) {
  return useQuery({
    queryKey: qk.findings(includeSuppressed),
    queryFn: () => fetchFindings(undefined, includeSuppressed),
  });
}

export function useFindingDetail(findingId: string | undefined) {
  return useQuery({
    queryKey: qk.findingDetail(findingId ?? ""),
    queryFn: () => fetchFindingDetail(findingId!),
    enabled: !!findingId,
  });
}

// useTriage fetches a single finding's triage state standalone. Used by
// the dossier header (the list carries triage inline, so rows do not call
// this — avoiding an N+1 of per-row requests).
export function useTriage(fingerprint: string | undefined) {
  return useQuery({
    queryKey: qk.triage(fingerprint ?? ""),
    queryFn: () => getTriage(fingerprint!),
    enabled: !!fingerprint,
  });
}

// useSetTriage writes a triage decision with field-level PATCH semantics: a
// status-only change PATCHes just the status and PRESERVES any existing note
// (an omitted field is left untouched server-side), while an explicit note —
// including an empty string to clear it — is sent as provided. This replaces
// the old PUT-everything behavior that clobbered a stored note to "" on every
// status change. On success it invalidates the whole findings namespace (so
// inline triage in every list variant refreshes) plus the edited
// fingerprint's standalone triage query.
export function useSetTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: {
      fingerprint: string;
      status?: TriageStatus;
      note?: string;
    }) => patchTriage(vars.fingerprint, { status: vars.status, note: vars.note }),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: qk.findings() });
      void qc.invalidateQueries({ queryKey: qk.triage(vars.fingerprint) });
    },
  });
}

// useReplaceTriage does a full PUT (status + note together). Use only when a
// caller genuinely intends to set both fields at once; prefer useSetTriage for
// note-preserving status edits.
export function useReplaceTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: {
      fingerprint: string;
      status: TriageStatus;
      note: string;
    }) => setTriage(vars.fingerprint, vars.status, vars.note),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: qk.findings() });
      void qc.invalidateQueries({ queryKey: qk.triage(vars.fingerprint) });
    },
  });
}
