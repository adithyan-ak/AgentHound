import { useState } from "react";
import { Check, Copy, FileWarning } from "lucide-react";
import type { InstructionEvidence, InstructionSignal } from "@entities/finding/model";
import { WidgetCard } from "@shared/ui/widgets";

export function InstructionEvidencePanel({ evidence }: { evidence: InstructionEvidence }) {
  return (
    <WidgetCard
      title="Matched Instruction Evidence"
      icon={FileWarning}
      action={
        evidence.truncated ? (
          <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-amber-400">
            {evidence.signals.length} of {evidence.total_signals} signals retained
          </span>
        ) : (
          <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
            {evidence.total_signals} signal{evidence.total_signals === 1 ? "" : "s"}
          </span>
        )
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          {evidence.verdict === "poisoning"
            ? "Strong compound evidence was observed in an applicable instruction scope. Review the exact content below before the file is trusted."
            : "Suspicious instruction content was observed. This signal requires review and does not by itself establish malicious intent or execution."}
        </p>
        {evidence.signals.map((signal, index) => (
          <SignalCard key={`${signal.rule_id}:${signal.raw_offset}:${index}`} evidence={evidence} signal={signal} index={index} />
        ))}
      </div>
    </WidgetCard>
  );
}

function SignalCard({
  evidence,
  signal,
  index,
}: {
  evidence: InstructionEvidence;
  signal: InstructionSignal;
  index: number;
}) {
  const [copied, setCopied] = useState(false);
  const excerpt = `${signal.context_before}${signal.match}${signal.context_after}`;

  function copyExcerpt() {
    void navigator.clipboard.writeText(excerpt);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <article className="overflow-hidden rounded-[4px] border border-border bg-black/25">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/70 px-3 py-2">
        <div className="min-w-0">
          <p className="font-mono text-xs font-semibold text-foreground">
            {String(index + 1).padStart(2, "0")} · {signal.label}
          </p>
          <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
            {signal.rule_id} · {signal.strength} · {signal.severity} · {evidence.path}:{signal.line}:{signal.column}
          </p>
        </div>
        <button
          type="button"
          onClick={copyExcerpt}
          className="inline-flex h-7 items-center gap-1 rounded-[3px] border border-border bg-black/30 px-2 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground transition-colors hover:text-foreground"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy excerpt"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-words px-3 py-3 font-mono text-[12px] leading-5 text-foreground/75">
        <span>{visibleCharacters(signal.context_before)}</span>
        <mark className="rounded-[2px] bg-amber-400/20 px-0.5 text-amber-200 ring-1 ring-inset ring-amber-400/40">
          {visibleCharacters(signal.match)}
        </mark>
        <span>{visibleCharacters(signal.context_after)}</span>
      </pre>
      {signal.decoded_excerpt && (
        <div className="border-t border-border/70 px-3 py-2">
          <p className="mb-1 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
            Decoded payload preview
          </p>
          <pre className="whitespace-pre-wrap break-words font-mono text-[11px] leading-5 text-foreground/75">
            {visibleCharacters(signal.decoded_excerpt)}
          </pre>
        </div>
      )}
    </article>
  );
}

const INVISIBLE_CHARACTERS: Record<string, string> = {
  "\u200b": "⟦U+200B ZERO WIDTH SPACE⟧",
  "\u200c": "⟦U+200C ZERO WIDTH NON-JOINER⟧",
  "\u200d": "⟦U+200D ZERO WIDTH JOINER⟧",
  "\ufeff": "⟦U+FEFF ZERO WIDTH NO-BREAK SPACE⟧",
  "\u202e": "⟦U+202E RIGHT-TO-LEFT OVERRIDE⟧",
};

export function visibleCharacters(value: string): string {
  return Array.from(value, (character) => INVISIBLE_CHARACTERS[character] ?? character).join("");
}
