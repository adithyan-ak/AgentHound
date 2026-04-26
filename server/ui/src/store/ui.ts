import { create } from "zustand";

interface UIState {
  sidebarOpen: boolean;
  activeView: string;
}

interface UIActions {
  openSidebar: () => void;
  closeSidebar: () => void;
  toggleSidebar: () => void;
  setActiveView: (view: string) => void;
}

export const useUIStore = create<UIState & UIActions>()((set) => ({
  sidebarOpen: false,
  activeView: "dashboard",

  openSidebar: () => set({ sidebarOpen: true }),

  closeSidebar: () => set({ sidebarOpen: false }),

  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),

  setActiveView: (view) => set({ activeView: view }),
}));
