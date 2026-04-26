import { api } from "./client";
import type { Scan } from "./types";

export async function fetchScans(limit = 50, offset = 0): Promise<Scan[]> {
  return api
    .get("scans", {
      searchParams: { limit: String(limit), offset: String(offset) },
    })
    .json<Scan[]>();
}

export async function fetchScan(id: string): Promise<Scan> {
  return api.get(`scans/${encodeURIComponent(id)}`).json<Scan>();
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`scans/${encodeURIComponent(id)}`);
}
