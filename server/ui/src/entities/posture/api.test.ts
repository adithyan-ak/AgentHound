import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchProjectionState,
  hasLimitedPublishedInstructionCoverage,
  type ProjectionState,
} from "./api";

const getMock = vi.hoisted(() => vi.fn());

vi.mock("@shared/api/client", () => ({
  api: { get: getMock },
}));

describe("fetchProjectionState", () => {
  beforeEach(() => {
    getMock.mockReset();
  });

  it("decodes active instruction coverage roots", async () => {
    getMock.mockReturnValue({
      json: vi.fn().mockResolvedValue({
        status: "complete",
        dirty_coverage: [],
        active_coverage_roots: [
          {
            coverage_key: `config:instruction-deep:sha256:${"a".repeat(64)}`,
            mode: "deep",
            state: "truncated",
            scan_id: "scan-deep",
            observed_at: "2026-07-24T18:00:00Z",
            registry_contract: {
              generation: 1,
              digest: `sha256:${"b".repeat(64)}`,
            },
            contract_current: true,
          },
        ],
        updated_at: "2026-07-24T18:00:01Z",
      }),
    });

    const posture = await fetchProjectionState();

    expect(posture.active_coverage_roots).toEqual([
      expect.objectContaining({
        mode: "deep",
        state: "truncated",
        scan_id: "scan-deep",
        contract_current: true,
      }),
    ]);
  });

  it("rejects malformed root contracts", async () => {
    getMock.mockReturnValue({
      json: vi.fn().mockResolvedValue({
        status: "complete",
        dirty_coverage: [],
        active_coverage_roots: [
          {
            coverage_key: "root",
            mode: "deep",
            state: "complete",
            scan_id: "scan",
            observed_at: "2026-07-24T18:00:00Z",
            registry_contract: { generation: "old", digest: "bad" },
            contract_current: false,
          },
        ],
        updated_at: "2026-07-24T18:00:01Z",
      }),
    });

    await expect(fetchProjectionState()).rejects.toThrow(
      "active_coverage_roots[0] is invalid",
    );
  });
});

describe("hasLimitedPublishedInstructionCoverage", () => {
  const posture: ProjectionState = {
    status: "complete",
    scan_id: "scan-1",
    dirty_coverage: [],
    active_coverage_roots: [
      {
        coverage_key: "root",
        mode: "exact_project",
        state: "complete",
        scan_id: "scan-1",
        observed_at: "2026-07-24T18:00:00Z",
        registry_contract: { generation: 1, digest: "sha256:old" },
        contract_current: false,
      },
    ],
    updated_at: "2026-07-24T18:00:01Z",
    published_scan_id: "scan-1",
    published_revision: 1,
  };

  it("treats an outdated active root contract as limited", () => {
    expect(hasLimitedPublishedInstructionCoverage(posture, "scan-1")).toBe(true);
  });

  it("does not apply one publication's limitation to another scan", () => {
    expect(hasLimitedPublishedInstructionCoverage(posture, "scan-2")).toBe(false);
  });
});
