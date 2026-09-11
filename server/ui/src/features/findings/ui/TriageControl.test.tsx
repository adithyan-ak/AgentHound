import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { expect, it, vi } from "vitest";
import { TriageControl } from "./TriageControl";
import { setTriage } from "@entities/finding/api";

vi.mock("@entities/finding/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@entities/finding/api")>(),
  setTriage: vi.fn(),
}));

it("shows pending and rejected saves and retries the same decision without navigating the row", async () => {
  let reject!: (error: Error) => void;
  const write = vi.mocked(setTriage);
  write.mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
  const navigate = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}>
      <div onClick={navigate}><TriageControl findingId="finding-1" status="new" /></div>
    </QueryClientProvider>,
  );
  fireEvent.keyDown(screen.getByRole("button", { name: "Set triage status" }), { key: "ArrowDown" });
  fireEvent.click(await screen.findByRole("menuitem", { name: "Triaging" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Set triage status" })).toBeDisabled());
  await act(async () => reject(new Error("write rejected")));
  expect(await screen.findByRole("alert")).toHaveTextContent("Status save failed");
  write.mockResolvedValueOnce({ status: "triaging", note: "", updated_at: "2026-09-10T00:00:00Z" });
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  expect(write).toHaveBeenLastCalledWith("finding-1", "triaging", undefined);
  expect(write).toHaveBeenCalledTimes(2);
  expect(navigate).not.toHaveBeenCalled();
});
