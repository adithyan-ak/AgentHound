import { useMemo, useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchFindings } from "@/api/analysis";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { InfoTip } from "./InfoTip";
import { Skeleton } from "@/components/ui/skeleton";

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_FILL: Record<string, string> = {
  critical: "linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)",
  high: "linear-gradient(135deg, #d97706 0%, #b45309 100%)",
  medium: "linear-gradient(135deg, #a16207 0%, #854d0e 100%)",
  low: "linear-gradient(135deg, #475569 0%, #334155 100%)",
};

const DEFAULT_FILL = "linear-gradient(135deg, #475569 0%, #334155 100%)";

function getFill(sev: string): string {
  return SEVERITY_FILL[sev] ?? DEFAULT_FILL;
}

function worstSeverity(findings: { severity: string }[]): string {
  let worst = "low";
  for (const f of findings) {
    if ((SEVERITY_RANK[f.severity] ?? 4) < (SEVERITY_RANK[worst] ?? 4)) {
      worst = f.severity;
    }
  }
  return worst;
}

interface Rect {
  name: string;
  count: number;
  worst: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

interface SizedItem {
  name: string;
  count: number;
  worst: string;
  area: number;
}

function worstAspectRatio(row: SizedItem[], rowLen: number): number {
  let worst = 0;
  for (const r of row) {
    const itemLen = r.area / rowLen;
    const ratio = Math.max(rowLen / itemLen, itemLen / rowLen);
    if (ratio > worst) worst = ratio;
  }
  return worst;
}

function squarify(
  items: { name: string; count: number; worst: string }[],
  W: number,
  H: number,
): Rect[] {
  if (items.length === 0 || W <= 0 || H <= 0) return [];

  const totalCount = items.reduce((s, d) => s + d.count, 0);
  if (totalCount === 0) return [];

  const totalArea = W * H;
  const sized: SizedItem[] = items.map((d) => ({
    ...d,
    area: (d.count / totalCount) * totalArea,
  }));

  const rects: Rect[] = [];
  let x = 0, y = 0, w = W, h = H;
  let i = 0;

  while (i < sized.length) {
    const first = sized[i]!;
    const isWide = w >= h;
    const side = isWide ? h : w;

    const row: SizedItem[] = [first];
    let rowArea = first.area;
    let rowLen = rowArea / side;
    let ratio = worstAspectRatio(row, rowLen);
    i++;

    while (i < sized.length) {
      const next = sized[i]!;
      const candidate = [...row, next];
      const candArea = rowArea + next.area;
      const candLen = candArea / side;
      const candRatio = worstAspectRatio(candidate, candLen);

      if (candRatio > ratio) break;

      row.push(next);
      rowArea = candArea;
      rowLen = candLen;
      ratio = candRatio;
      i++;
    }

    let offset = 0;
    for (const item of row) {
      const itemLen = item.area / rowLen;
      if (isWide) {
        rects.push({ name: item.name, count: item.count, worst: item.worst, x, y: y + offset, w: rowLen, h: itemLen });
      } else {
        rects.push({ name: item.name, count: item.count, worst: item.worst, x: x + offset, y, w: itemLen, h: rowLen });
      }
      offset += itemLen;
    }

    if (isWide) {
      x += rowLen;
      w -= rowLen;
    } else {
      y += rowLen;
      h -= rowLen;
    }
  }

  return rects;
}

export function RiskChart() {
  const [dims, setDims] = useState({ w: 0, h: 0 });

  const measuredRef = useCallback((el: HTMLDivElement | null) => {
    if (!el) return;
    setDims({ w: el.clientWidth, h: el.clientHeight });
  }, []);

  const { data: findings, isLoading } = useQuery({
    queryKey: ["dashboard", "findings-by-category"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  const categories = useMemo(() => {
    const map = new Map<string, { severity: string }[]>();
    for (const f of findings ?? []) {
      const list = map.get(f.category) ?? [];
      list.push(f);
      map.set(f.category, list);
    }
    return Array.from(map.entries())
      .map(([name, items]) => ({
        name,
        count: items.length,
        worst: worstSeverity(items),
      }))
      .sort((a, b) => b.count - a.count);
  }, [findings]);

  const rects = useMemo(
    () => squarify(categories, dims.w, dims.h),
    [categories, dims.w, dims.h],
  );

  const hasData = categories.length > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
          Findings by Category
          <InfoTip text="Treemap of security findings grouped by category. Rectangle size shows finding count. Color indicates worst severity in that category." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-52 w-full" />
        ) : !hasData ? (
          <div className="flex h-52 items-center justify-center text-sm text-muted-foreground">
            No findings yet
          </div>
        ) : (
          <div ref={measuredRef} className="relative h-52 w-full overflow-hidden rounded-lg">
            {rects.map((r) => (
              <div
                key={r.name}
                className="absolute overflow-hidden"
                style={{
                  left: r.x,
                  top: r.y,
                  width: r.w,
                  height: r.h,
                  padding: 2,
                }}
              >
                <div
                  className="flex h-full w-full flex-col items-center justify-center rounded-md"
                  style={{ background: getFill(r.worst) }}
                >
                  {r.w > 55 && r.h > 40 && (
                    <span className="px-1 text-center text-[11px] font-medium leading-tight text-white/80">
                      {r.name}
                    </span>
                  )}
                  <span
                    className="font-mono font-bold text-white"
                    style={{ fontSize: Math.min(Math.max(r.h * 0.25, 14), 28) }}
                  >
                    {r.count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
