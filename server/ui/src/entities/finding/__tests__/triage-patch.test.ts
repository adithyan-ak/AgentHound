import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@shared/api/client", () => ({
  api: {
    patch: vi.fn(() => ({
      json: vi.fn().mockResolvedValue({ status: "confirmed", note: "" }),
    })),
  },
}));

import { api } from "@shared/api/client";
import { patchTriage } from "../api";

const patch = vi.mocked(api.patch);

describe("patchTriage — field-level preserve/clear semantics", () => {
  beforeEach(() => {
    patch.mockClear();
  });

  it("OMITS an undefined field so the server preserves the stored value", async () => {
    await patchTriage("0123456789abcdef", { status: "confirmed" });
    const opts = patch.mock.calls[0]![1] as { json: Record<string, string> };
    // note is not sent → server keeps the existing note.
    expect(opts.json).toEqual({ status: "confirmed" });
    expect("note" in opts.json).toBe(false);
  });

  it("SENDS an explicit empty note so the server clears it", async () => {
    await patchTriage("0123456789abcdef", { note: "" });
    const opts = patch.mock.calls[0]![1] as { json: Record<string, string> };
    expect(opts.json).toEqual({ note: "" });
    expect("status" in opts.json).toBe(false);
  });

  it("sends both fields when both are provided", async () => {
    await patchTriage("0123456789abcdef", {
      status: "accepted-risk",
      note: "known dev box",
    });
    const opts = patch.mock.calls[0]![1] as { json: Record<string, string> };
    expect(opts.json).toEqual({ status: "accepted-risk", note: "known dev box" });
  });
});
