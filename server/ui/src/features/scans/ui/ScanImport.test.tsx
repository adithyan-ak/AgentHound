import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ScanImport, validateScanFile } from "./ScanImport";

vi.mock("@entities/scan/api", () => ({
  uploadScan: vi.fn(),
}));

import { uploadScan } from "@entities/scan/api";

const mockedUploadScan = vi.mocked(uploadScan);

// ScanImport now uploads via the useUploadScan mutation hook, so it needs a
// QueryClient in context.
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>{children}</MemoryRouter>
      </QueryClientProvider>
    );
  };
}

function makeJSONFile(name: string, content: string): File {
  return new File([content], name, { type: "application/json" });
}

function makeOversizeFile(name: string): File {
  // Build a sparse 100 MB + 1 byte file by spoofing the size property
  // on a tiny File. Browser File implementations expose size via the
  // underlying blob length; jsdom honors what we put in the constructor.
  // To avoid actually allocating 100 MB in jsdom, override file.size.
  const f = new File(["x"], name, { type: "application/json" });
  Object.defineProperty(f, "size", { value: 100 * 1024 * 1024 + 1 });
  return f;
}

const validScanJSON = JSON.stringify({
  meta: {
    version: 1,
    type: "agenthound-ingest",
    collector: "config",
    collector_version: "0.1.0",
    timestamp: "2026-04-23T12:00:00Z",
    scan_id: "test-scan-1",
  },
  graph: { nodes: [], edges: [] },
});

describe("ScanImport", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uploads a dropped JSON file and calls onSuccess", async () => {
    mockedUploadScan.mockResolvedValue({
      scan_id: "test-scan-1",
      nodes_written: 5,
      edges_written: 3,
    });
    const onSuccess = vi.fn();

    render(<ScanImport open={true} onClose={() => {}} onSuccess={onSuccess} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const file = makeJSONFile("scan.json", validScanJSON);

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [file] },
    });

    await waitFor(() => {
      expect(mockedUploadScan).toHaveBeenCalledWith(file);
    });
    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalled();
    });
    expect(screen.getByText(/imported scan\.json/i)).toBeInTheDocument();
    expect(screen.getByText(/5 nodes, 3 edges written/i)).toBeInTheDocument();
  });

  it("shows an error and does not upload when the file is not valid JSON", async () => {
    const onSuccess = vi.fn();
    render(<ScanImport open={true} onClose={() => {}} onSuccess={onSuccess} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const badFile = makeJSONFile("scan.json", "not json {{");

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [badFile] },
    });

    await waitFor(() => {
      expect(screen.getByText(/import failed/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/not valid json/i)).toBeInTheDocument();
    expect(mockedUploadScan).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("shows an error when the server rejects the upload", async () => {
    mockedUploadScan.mockRejectedValue(
      new Error("server error (500): check server logs"),
    );
    const onSuccess = vi.fn();

    render(<ScanImport open={true} onClose={() => {}} onSuccess={onSuccess} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const file = makeJSONFile("scan.json", validScanJSON);

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [file] },
    });

    await waitFor(() => {
      expect(screen.getByText(/import failed/i)).toBeInTheDocument();
    });
    expect(
      screen.getByText(/server error \(500\): check server logs/i),
    ).toBeInTheDocument();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("rejects files larger than 100 MB without reading them", async () => {
    render(<ScanImport open={true} onClose={() => {}} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const huge = makeOversizeFile("huge.json");

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [huge] },
    });

    await waitFor(() => {
      expect(screen.getByText(/file too large/i)).toBeInTheDocument();
    });
    expect(mockedUploadScan).not.toHaveBeenCalled();
  });

  it("rejects files whose name does not end in .json", async () => {
    render(<ScanImport open={true} onClose={() => {}} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const wrong = new File(["{}"], "scan.exe", { type: "application/json" });

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [wrong] },
    });

    await waitFor(() => {
      expect(screen.getByText(/must be a \.json file/i)).toBeInTheDocument();
    });
    expect(mockedUploadScan).not.toHaveBeenCalled();
  });

  it("rejects files with a non-JSON MIME type when one is set", async () => {
    render(<ScanImport open={true} onClose={() => {}} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const wrong = new File(["{}"], "scan.json", {
      type: "application/octet-stream",
    });

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [wrong] },
    });

    await waitFor(() => {
      expect(screen.getByText(/must be a \.json file/i)).toBeInTheDocument();
    });
    expect(mockedUploadScan).not.toHaveBeenCalled();
  });

  it("accepts files with empty MIME type (drag-drop from some OSes)", async () => {
    mockedUploadScan.mockResolvedValue({
      scan_id: "test-scan-2",
      nodes_written: 1,
      edges_written: 0,
    });
    render(<ScanImport open={true} onClose={() => {}} />, {
      wrapper: createWrapper(),
    });

    const dropzone = screen.getByTestId("dropzone");
    const file = new File([validScanJSON], "scan.json", { type: "" });

    fireEvent.drop(dropzone, {
      dataTransfer: { files: [file] },
    });

    await waitFor(() => {
      expect(mockedUploadScan).toHaveBeenCalledWith(file);
    });
  });
});

describe("validateScanFile", () => {
  it("returns null for a small .json file", () => {
    const ok = new File(["{}"], "scan.json", { type: "application/json" });
    expect(validateScanFile(ok)).toBeNull();
  });

  it("rejects a file >100 MB", () => {
    const f = new File(["x"], "scan.json", { type: "application/json" });
    Object.defineProperty(f, "size", { value: 100 * 1024 * 1024 + 1 });
    expect(validateScanFile(f)).toMatch(/too large/i);
  });

  it("rejects a non-.json extension", () => {
    const f = new File(["{}"], "scan.txt", { type: "application/json" });
    expect(validateScanFile(f)).toMatch(/\.json file/i);
  });

  it("rejects an explicit non-JSON MIME", () => {
    const f = new File(["{}"], "scan.json", {
      type: "application/octet-stream",
    });
    expect(validateScanFile(f)).toMatch(/\.json file/i);
  });

  it("accepts an empty MIME type", () => {
    const f = new File(["{}"], "scan.json", { type: "" });
    expect(validateScanFile(f)).toBeNull();
  });
});
