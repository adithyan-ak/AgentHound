import { useState } from "react";
import { Copy, Check } from "lucide-react";

interface CopyableCodeBlockProps {
  code: string;
}

export function CopyableCodeBlock({ code }: CopyableCodeBlockProps) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="relative rounded border border-slate-700 bg-slate-900/80 p-2.5 mt-1.5">
      <button
        onClick={handleCopy}
        className="absolute top-1.5 right-1.5 p-1 rounded hover:bg-slate-700 transition-colors"
        title="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3 w-3 text-green-400" />
        ) : (
          <Copy className="h-3 w-3 text-muted-foreground" />
        )}
      </button>
      <pre className="text-[10px] text-foreground font-mono whitespace-pre-wrap pr-6">
        {code}
      </pre>
    </div>
  );
}
