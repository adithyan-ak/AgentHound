import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PropertiesTab } from "./PropertiesTab";

const writeText = vi.fn();

describe("PropertiesTab credential values", () => {
  beforeEach(() => {
    writeText.mockReset();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
  });

  it("masks, reveals, copies, and resets an exact credential value", () => {
    const { rerender } = render(
      <PropertiesTab
        node={{
          id: "credential-1",
          kinds: ["Credential"],
          properties: { value: "first-secret" },
        }}
      />,
    );

    expect(screen.queryByText("first-secret")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reveal credential value" }));
    expect(screen.getByText("first-secret")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy credential value" }));
    expect(writeText).toHaveBeenCalledWith("first-secret");
    expect(screen.getByText("Copied")).toBeInTheDocument();

    rerender(
      <PropertiesTab
        node={{
          id: "credential-2",
          kinds: ["Credential"],
          properties: { value: "second-secret" },
        }}
      />,
    );
    expect(screen.queryByText("second-secret")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reveal credential value" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Copy")).toBeInTheDocument();
  });

  it("summarizes instruction evidence without rendering the raw JSON", () => {
    const raw = JSON.stringify({ verdict: "signal", total_signals: 2, truncated: false, signals: [] });
    render(
      <PropertiesTab
        node={{
          id: "instruction-1",
          kinds: ["InstructionFile"],
          properties: { path: "/work/AGENTS.md", instruction_evidence_json: raw },
        }}
      />,
    );
    expect(screen.getByText("signal · 2 signals")).toBeInTheDocument();
    expect(screen.queryByText(raw)).not.toBeInTheDocument();
  });
});
