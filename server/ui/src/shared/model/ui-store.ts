import { create } from "zustand";

interface UIState {
  activeView: string;
}

interface UIActions {
  setActiveView: (view: string) => void;
}

export const useUIStore = create<UIState & UIActions>()((set) => ({
  activeView: "dashboard",

  setActiveView: (view) => set({ activeView: view }),
}));
