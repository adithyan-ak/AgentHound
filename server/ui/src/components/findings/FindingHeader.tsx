import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Compass, Copy, Check } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { MiniHexIcon } from "./MiniHexIcon";
import { cn } from "@/lib/utils";
import { SEVERITY } from "@/theme/tokens";
import type { FindingDetail } from "@/api/types";

interface FindingHeaderProps {
  detail: FindingDetail;
  prevId: string | null;
  nextId: string | null;
  onCopyReport: () => void;
}

export function FindingHeader({ detail, prevId, nextId, onCopyReport }: FindingHeaderProps) {
  const navigate = useNavigate();
  const f = detail.finding;
  const sev = SEVERITY[f.severity] ?? SEVERITY.low!;
  const [copied, setCopied] = useState(false);

  const hops = detail.composite_props?.hops;

  function handleCopy() {
    onCopyReport();
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className={cn("rounded-lg p-5 border-l-4", sev.borderLeftClass)}>
      {/* Breadcrumb + nav */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <button onClick={() => navigate("/findings")} className="hover:text-foreground transition-colors">
            Findings
          </button>
          <span>/</span>
          <span className="capitalize">{f.severity}</span>
          <span>/</span>
          <span className="text-foreground truncate max-w-[300px]">{f.title}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            variant="outline"
            size="sm"
            disabled={!prevId}
            onClick={() => prevId && navigate(`/findings/${prevId}`)}
            className="h-7 px-2"
          >
            <ArrowLeft className="h-3.5 w-3.5 mr-1" /> Prev
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!nextId}
            onClick={() => nextId && navigate(`/findings/${nextId}`)}
            className="h-7 px-2"
          >
            Next <ArrowRight className="h-3.5 w-3.5 ml-1" />
          </Button>
        </div>
      </div>

      {/* Severity + title + actions */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <SeverityBadge severity={f.severity} className="mb-2 text-xs font-bold uppercase" />
          <h1 className="text-xl font-semibold text-foreground mb-2">{f.title}</h1>

          {/* Source -> Target */}
          <div className="flex items-center gap-2 mb-3 text-sm">
            <MiniHexIcon kind={f.source_kind} />
            <span className="text-foreground font-medium">{f.source_name || f.source_id.slice(0, 12)}</span>
            <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
            <MiniHexIcon kind={f.target_kind} />
            <span className="text-foreground font-medium">{f.target_name || f.target_id.slice(0, 12)}</span>
          </div>

          {/* Metadata chips */}
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="text-[10px] font-mono">
              {f.id.slice(0, 8)}
            </Badge>
            {typeof hops === "number" && (
              <Badge variant="outline" className="text-[10px]">
                {hops} hops
              </Badge>
            )}
            <Badge variant="outline" className="text-[10px]">
              {Math.round(f.confidence * 100)}% confidence
            </Badge>
            {f.owasp_map.map((tag) => (
              <Badge key={tag} variant="secondary" className="text-[10px] font-mono">
                {tag}
              </Badge>
            ))}
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-col gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-8"
            onClick={() => navigate("/explorer")}
          >
            <Compass className="h-3.5 w-3.5 mr-1.5" /> View in Explorer
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8"
            onClick={handleCopy}
          >
            {copied ? (
              <><Check className="h-3.5 w-3.5 mr-1.5 text-green-400" /> Copied</>
            ) : (
              <><Copy className="h-3.5 w-3.5 mr-1.5" /> Copy Report</>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
