import type { ReactNode } from "react";
import { AlertCircle, AlertTriangle } from "lucide-react";
import { cn } from "@shared/lib/utils";

interface DataStateNoticeProps {
  tone: "error" | "warning";
  title: string;
  children: ReactNode;
  className?: string;
}

export function DataStateNotice({
  tone,
  title,
  children,
  className,
}: DataStateNoticeProps) {
  const Icon = tone === "error" ? AlertCircle : AlertTriangle;
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "flex items-start gap-2 rounded-[3px] border px-3 py-2.5",
        tone === "error"
          ? "border-destructive/35 bg-destructive/10 text-destructive"
          : "border-amber-400/35 bg-amber-400/10 text-amber-200",
        className,
      )}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div className="min-w-0">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em]">
          {title}
        </p>
        <div className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
          {children}
        </div>
      </div>
    </div>
  );
}
