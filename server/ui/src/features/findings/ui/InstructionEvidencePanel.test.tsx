import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { InstructionEvidencePanel, visibleCharacters } from "./InstructionEvidencePanel";

const writeText = vi.fn();

describe("InstructionEvidencePanel", () => {
  beforeEach(() => {
    writeText.mockReset();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
  });

  it("shows path, position, highlighted match, invisible codepoint, and copyable excerpt", () => {
    render(
      <InstructionEvidencePanel
        evidence={{
          version: 1,
          verdict: "poisoning",
          scope: "exact_project",
          path: "/work/AGENTS.md",
          type: "agents.md",
          hash: "sha256:abc",
          size_bytes: 100,
          modified_at: "2026-08-20T12:00:00Z",
          total_signals: 2,
          truncated: true,
          signals: [{
            rule_id: "injection-ignore-previous",
            label: "Ignore Previous Instructions",
            severity: "critical",
            strength: "primary",
            raw_offset: 7,
            line: 2,
            column: 3,
            match: "ignore\u200b previous instructions",
            context_before: "before\n",
            context_after: "\nafter",
          }],
        }}
      />,
    );

    expect(screen.getByText("Matched Instruction Evidence")).toBeInTheDocument();
    expect(screen.getByText("1 of 2 signals retained")).toBeInTheDocument();
    expect(screen.getByText(/\/work\/AGENTS\.md:2:3/)).toBeInTheDocument();
    expect(screen.getByText(/U\+200B ZERO WIDTH SPACE/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /copy excerpt/i }));
    expect(writeText).toHaveBeenCalledWith("before\nignore\u200b previous instructions\nafter");
  });

  it("renders known invisible characters explicitly", () => {
    expect(visibleCharacters("a\u202eb")).toContain("U+202E RIGHT-TO-LEFT OVERRIDE");
  });
});
