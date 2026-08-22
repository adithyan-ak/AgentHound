import type { FindingEvidence } from "@entities/finding/model";

export function formatFindingEvidenceState(state: FindingEvidence["state"]): string {
  if (state === "verified") {
    return "Verified During Scan";
  }
  return state.replace(/_/g, " ");
}
