import { useMutation } from "@tanstack/react-query";
import {
  findShortestPath,
  findAllPaths,
  findWeightedPath,
} from "@/api/analysis";
import type { PathRequest } from "@/api/types";

export function useShortestPath() {
  return useMutation({
    mutationFn: (req: PathRequest) => findShortestPath(req),
  });
}

export function useAllPaths() {
  return useMutation({
    mutationFn: (req: PathRequest) => findAllPaths(req),
  });
}

export function useWeightedPath() {
  return useMutation({
    mutationFn: (req: PathRequest) => findWeightedPath(req),
  });
}
