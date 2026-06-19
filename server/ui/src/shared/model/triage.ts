import { create } from "zustand";
import { persist } from "zustand/middleware";
import { SEVERITY, ACCENT, SIGNAL_OK, TRIAGE_NEUTRAL } from "@shared/theme/tokens";

/**
 * Finding triage workflow state (shared kernel).
 *
 * A red-team engagement works a register of findings over time; this slice
 * tracks per-finding triage status + a freeform note so progress survives
 * reloads. Lives in shared (not the findings feature) so the explorer can also
 * read it later without a cross-feature import. Persisted under its own key.
 *
 * "new" is the implicit default (absence of an entry), so a fresh scan's
 * findings all read as New without seeding the map.
 */
export type TriageStatus =
  | "new"
  | "triaging"
  | "confirmed"
  | "accepted-risk"
  | "false-positive";

export const TRIAGE_ORDER: TriageStatus[] = [
  "new",
  "triaging",
  "confirmed",
  "accepted-risk",
  "false-positive",
];

export interface TriageMeta {
  label: string;
  short: string;
  color: string;
}

export const TRIAGE_META: Record<TriageStatus, TriageMeta> = {
  new: { label: "New", short: "NEW", color: TRIAGE_NEUTRAL },
  triaging: { label: "Triaging", short: "TRIAGE", color: ACCENT },
  confirmed: { label: "Confirmed", short: "CONFIRMED", color: SEVERITY.critical.solid },
  "accepted-risk": { label: "Accepted risk", short: "ACCEPTED", color: SEVERITY.info.solid },
  "false-positive": { label: "False positive", short: "FALSE+", color: SIGNAL_OK },
};

interface TriageState {
  status: Record<string, TriageStatus>;
  notes: Record<string, string>;
}

interface TriageActions {
  setStatus: (id: string, status: TriageStatus) => void;
  setNote: (id: string, note: string) => void;
  getStatus: (id: string) => TriageStatus;
  getNote: (id: string) => string;
  reset: () => void;
}

export const useTriageStore = create<TriageState & TriageActions>()(
  persist(
    (set, get) => ({
      status: {},
      notes: {},

      setStatus: (id, status) =>
        set((state) => {
          const next = { ...state.status };
          if (status === "new") delete next[id];
          else next[id] = status;
          return { status: next };
        }),

      setNote: (id, note) =>
        set((state) => {
          const next = { ...state.notes };
          if (note.trim() === "") delete next[id];
          else next[id] = note;
          return { notes: next };
        }),

      getStatus: (id) => get().status[id] ?? "new",
      getNote: (id) => get().notes[id] ?? "",

      reset: () => set({ status: {}, notes: {} }),
    }),
    {
      name: "agenthound-triage",
      partialize: (state) => ({ status: state.status, notes: state.notes }),
    },
  ),
);
