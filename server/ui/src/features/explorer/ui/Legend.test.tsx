import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useExplorerStore } from "../model/store";
import { Legend } from "./Legend";

describe("Legend relationship semantics", () => {
  beforeEach(() => {
    useExplorerStore.setState((state) => ({
      activeLens: "attack-surface",
      subPresets: {
        ...state.subPresets,
        "attack-surface": ["CAN_REACH"],
      },
    }));
  });

  it("uses target-neutral CAN_REACH wording without endpoint evidence", () => {
    render(<Legend />);

    expect(screen.getByTitle("Agent can reach target")).toBeInTheDocument();
    expect(screen.queryByTitle("Agent can reach resource")).not.toBeInTheDocument();
  });
});
