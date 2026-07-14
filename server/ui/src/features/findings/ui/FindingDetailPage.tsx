import { useParams, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { Stack, Sidebar } from "@shared/ui/layout";
import { isEditableTarget } from "@shared/lib";
import {
  findingDetailErrorPresentation,
  useFindingDetail,
} from "@entities/finding";
import { useFindingsNavigation } from "../model/useFindingsNavigation";
import { buildMarkdownReport } from "../lib/copy-report";
import { FindingHeader } from "./FindingHeader";
import { AttackPathDiagram } from "./AttackPathDiagram";
import { HopEvidenceTimeline } from "./HopEvidenceTimeline";
import { FindingImpact } from "./FindingImpact";
import { FindingRemediation } from "./FindingRemediation";
import { FindingReferences } from "./FindingReferences";
import { FindingVerification } from "./FindingVerification";

export function FindingDetailPage() {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const { data: detail, isLoading, error } = useFindingDetail(findingId);
  const { prevId, nextId } = useFindingsNavigation(findingId);

  // Shared hop focus links the attack-path strip and the hop-evidence timeline
  // into a single "spine": selecting a hop in one expands/scrolls the other.
  const [activeHop, setActiveHop] = useState<number | null>(null);

  // Reset the focused hop when navigating between findings.
  useEffect(() => {
    setActiveHop(null);
  }, [findingId]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (isEditableTarget(e.target)) return;
      if (e.key === "ArrowLeft" && prevId) navigate(`/findings/${prevId}`);
      if (e.key === "ArrowRight" && nextId) navigate(`/findings/${nextId}`);
      if (e.key === "Escape") navigate("/findings");
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [prevId, nextId, navigate]);

  if (isLoading) {
    return (
      <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
        <div className="mx-auto max-w-[88rem]">
          <Stack gap="0.75rem">
            <Skeleton className="h-36 w-full rounded-md" />
            <Skeleton className="h-44 w-full rounded-md" />
            <Sidebar
              sidePosition="right"
              sideWidth="22rem"
              contentMin="58%"
              side={
                <Stack gap="0.75rem">
                  <Skeleton className="h-32 w-full rounded-md" />
                  <Skeleton className="h-48 w-full rounded-md" />
                </Stack>
              }
              main={<Skeleton className="h-64 w-full rounded-md" />}
            />
          </Stack>
        </div>
      </div>
    );
  }

  if (error || !detail) {
    const presentation = findingDetailErrorPresentation(error);
    return (
      <div className="dashboard-bg flex min-h-full flex-col items-center justify-center gap-4 p-6 text-center">
        <div className="font-mono text-sm font-semibold uppercase tracking-[0.12em] text-foreground">
          {presentation.title}
        </div>
        <p className="max-w-md text-sm text-muted-foreground">
          {presentation.message}
        </p>
        <button
          onClick={() => navigate("/findings")}
          className="font-mono text-xs uppercase tracking-[0.08em] text-primary transition-colors hover:text-primary/80"
        >
          ▸ Back to Findings
        </button>
      </div>
    );
  }

  const f = detail.finding;

  function handleCopyReport() {
    const md = buildMarkdownReport(
      f,
      detail!.attack_path,
      detail!.remediation,
      detail!.snapshot,
    );
    navigator.clipboard.writeText(md);
  }

  return (
    <div className="dashboard-bg min-h-full p-3 sm:p-4 lg:p-5">
      <div className="mx-auto max-w-[88rem]">
        <Stack gap="0.75rem">
          <FindingHeader
            detail={detail}
            prevId={prevId}
            nextId={nextId}
            onCopyReport={handleCopyReport}
          />

          <AttackPathDiagram
            path={detail.attack_path}
            severity={f.severity}
            sourceId={f.source_id}
            sourceName={f.source_name}
            sourceKind={f.source_kind}
            targetId={f.target_id}
            targetName={f.target_name}
            targetKind={f.target_kind}
            activeHop={activeHop}
            onHopSelect={setActiveHop}
          />

          <Sidebar
            sidePosition="right"
            sideWidth="22rem"
            contentMin="58%"
            side={
              <Stack gap="0.75rem">
                <FindingVerification evidence={f.evidence} />
                <FindingImpact impact={detail.impact} path={detail.attack_path} />
                <FindingRemediation steps={detail.remediation} />
                <FindingReferences finding={f} />
              </Stack>
            }
            main={
              <HopEvidenceTimeline
                path={detail.attack_path}
                activeHop={activeHop}
                onHopSelect={setActiveHop}
              />
            }
          />
        </Stack>
      </div>
    </div>
  );
}
