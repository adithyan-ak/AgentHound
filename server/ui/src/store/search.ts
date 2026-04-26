import { create } from "zustand";

interface SearchResult {
  id: string;
  name: string;
  kind: string;
}

interface SearchState {
  query: string;
  results: SearchResult[];
}

interface SearchActions {
  setQuery: (query: string) => void;
  setResults: (results: SearchResult[]) => void;
  clear: () => void;
}

export const useSearchStore = create<SearchState & SearchActions>()((set) => ({
  query: "",
  results: [],

  setQuery: (query) => set({ query }),

  setResults: (results) => set({ results }),

  clear: () => set({ query: "", results: [] }),
}));
