import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  patch: vi.fn(),
  json: vi.fn(),
}));

vi.mock("@shared/api/client", () => ({
  api: {
    patch: mocks.patch,
  },
}));

import { setTriage } from "@entities/finding/api";

describe("setTriage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.json.mockResolvedValue({
      status: "confirmed",
      note: "preserved",
      updated_at: "2026-07-11T00:00:00Z",
    });
    mocks.patch.mockReturnValue({ json: mocks.json });
  });

  it("omits note for a status-only update", async () => {
    await setTriage("aaaaaaaaaaaaaaaa", "confirmed");

    expect(mocks.patch).toHaveBeenCalledWith(
      "findings/triage/aaaaaaaaaaaaaaaa",
      { json: { status: "confirmed" } },
    );
  });

  it("sends an explicitly cleared note", async () => {
    await setTriage("aaaaaaaaaaaaaaaa", "confirmed", "");

    expect(mocks.patch).toHaveBeenCalledWith(
      "findings/triage/aaaaaaaaaaaaaaaa",
      { json: { status: "confirmed", note: "" } },
    );
  });
});
